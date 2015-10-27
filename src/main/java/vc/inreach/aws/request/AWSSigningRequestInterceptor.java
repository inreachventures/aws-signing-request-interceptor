package vc.inreach.aws.request;

import com.google.common.base.*;
import com.google.common.collect.ImmutableMap;
import com.google.common.io.ByteStreams;
import org.apache.http.*;
import org.apache.http.client.methods.HttpRequestWrapper;
import org.apache.http.message.BasicHeader;
import org.apache.http.protocol.HttpContext;

import java.io.IOException;
import java.util.Map;
import java.util.stream.Collectors;

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
        final HttpEntityEnclosingRequest original = (HttpEntityEnclosingRequest) ((HttpRequestWrapper) request).getOriginal();
        return Optional.fromNullable(original.getEntity()).transform(TO_BYTE_ARRAY);
    }

    private Header[] headers(Map<String, Object> from) {
        return from.entrySet().stream()
                .map(entry -> new BasicHeader(entry.getKey(), entry.getValue().toString()))
                .collect(Collectors.toList())
                .toArray(new Header[from.size()]);
    }

    private static final Function<HttpEntity, byte[]> TO_BYTE_ARRAY = entity -> {
        try {
            return ByteStreams.toByteArray(entity.getContent());
        } catch (IOException e) {
            throw Throwables.propagate(e);
        }
    };
}
