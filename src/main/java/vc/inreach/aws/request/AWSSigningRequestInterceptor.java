package vc.inreach.aws.request;

import java.io.IOException;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.client.methods.HttpRequestWrapper;
import org.apache.http.message.BasicHeader;
import org.apache.http.protocol.HttpContext;

import com.google.common.base.Function;
import com.google.common.base.Optional;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.base.Throwables;
import com.google.common.collect.Collections2;
import com.google.common.collect.ImmutableMap;
import com.google.common.io.ByteStreams;

public class AWSSigningRequestInterceptor implements HttpRequestInterceptor {

    private static final Splitter.MapSplitter SPLITTER = Splitter.on('&').trimResults().withKeyValueSeparator('=');

    private final AWSSigner signer;

    public AWSSigningRequestInterceptor(AWSSigner signer) {
        this.signer = signer;
    }

    @Override
    public void process(HttpRequest request, HttpContext context) throws HttpException, IOException {
        request.setHeaders(headers(signer.getSignedHeaders(
                path(request),
                request.getRequestLine().getMethod(),
                params(request),
                headers(request),
                body(request))
                ));
    }

    private Map<String, String> params(HttpRequest request) {
        final String query = ((HttpRequestWrapper) request).getURI().getQuery();
        if (Strings.isNullOrEmpty(query)) {
            return ImmutableMap.of();
        }
        return SPLITTER.split(query);
    }

    private String path(HttpRequest request) {
        return ((HttpRequestWrapper) request).getURI().getPath();
    }

    private Map<String, Object> headers(HttpRequest request) {
        final ImmutableMap.Builder<String, Object> headers = ImmutableMap.builder();

        for (Header header : request.getAllHeaders()) {
            headers.put(header.getName(), header.getValue());
        }

        return headers.build();
    }

    private Optional<byte[]> body(HttpRequest request) throws IOException {
        final HttpEntityEnclosingRequest original = (HttpEntityEnclosingRequest) ((HttpRequestWrapper) request)
                .getOriginal();
        return Optional.fromNullable(original.getEntity()).transform(TO_BYTE_ARRAY);
    }

    private Header[] headers(Map<String, Object> from) {
        Function<Entry<String, Object>, BasicHeader> function = new Function<Map.Entry<String, Object>, BasicHeader>() {
            @Override
            public BasicHeader apply(Entry<String, Object> entry) {
                return new BasicHeader(entry.getKey(), entry.getValue().toString());
            }
        };
        return Collections2.transform(from.entrySet(), function).toArray(new Header[from.size()]);
    }

    private static final Function<HttpEntity, byte[]> TO_BYTE_ARRAY = new Function<HttpEntity, byte[]>() {
        @Override
        public byte[] apply(HttpEntity entity) {
            try {
                return ByteStreams.toByteArray(entity.getContent());
            } catch (IOException e) {
                throw Throwables.propagate(e);
            }
        }
    };
}
