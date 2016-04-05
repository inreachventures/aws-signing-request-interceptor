package vc.inreach.aws.request;

import com.google.common.collect.ImmutableListMultimap;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Multimap;
import org.apache.http.Header;
import org.apache.http.ProtocolVersion;
import org.apache.http.client.methods.HttpRequestWrapper;
import org.apache.http.message.BasicRequestLine;
import org.apache.http.protocol.HttpContext;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.net.URI;

import static org.mockito.Matchers.anyMapOf;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class AWSSigningRequestInterceptorTest {

    @Mock
    private AWSSigner signer;
    @Mock
    private HttpRequestWrapper request;
    @Mock
    private HttpContext context;

    private AWSSigningRequestInterceptor interceptor;

    @Before
    public void setUp() throws Exception {
        interceptor = new AWSSigningRequestInterceptor(signer);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void queryParamsSupportValuesWithEquals() throws Exception {
        final String key = "scroll_id";
        final String value = "c2NhbjsxOzc3Mjo5WGljUUFNeVJGcVdDSzBjaUVQcDJ3OzE7dG90YWxfaGl0czo1NTg0Ow==";
        final String url = "http://someurl.com?" + key + "=" + value;
        final Multimap<String, String> queryParams = ImmutableListMultimap.of(key, value);

        when(signer.getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMapOf(String.class, Object.class), any(com.google.common.base.Optional.class))).thenReturn(ImmutableMap.of());
        when(request.getURI()).thenReturn(new URI(url));
        when(request.getRequestLine()).thenReturn(new BasicRequestLine("GET", url, new ProtocolVersion("HTTP", 1, 1)));
        when(request.getAllHeaders()).thenReturn(new Header[]{});
        when(request.getOriginal()).thenReturn(request);

        interceptor.process(request, context);

        verify(request).setHeaders(new Header[]{});
        verify(signer).getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMapOf(String.class, Object.class), any(com.google.common.base.Optional.class));
    }
}
