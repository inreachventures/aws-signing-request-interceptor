package vc.inreach.aws.request;

import com.amazonaws.util.SdkHttpUtils;
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
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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

    @Test
    public void noQueryParams() throws Exception {
        final String url = "http://someurl.com";
        final Multimap<String, String> queryParams = ImmutableListMultimap.of();

        when(signer.getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMapOf(String.class, Object.class), any(com.google.common.base.Optional.class))).thenReturn(ImmutableMap.of());
        mockRequest(url);

        interceptor.process(request, context);

        verify(request).setHeaders(new Header[]{});
        verify(signer).getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMapOf(String.class, Object.class), any(com.google.common.base.Optional.class));
    }


    @Test
    public void queryParamsSupportValuesWithSpaceEncodedAsPlus() throws Exception {
        final String url = "http://someurl.com?a=b+c";
        final Multimap<String, String> queryParams = ImmutableListMultimap.of("a", "b c");

        when(signer.getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMapOf(String.class, Object.class), any(com.google.common.base.Optional.class))).thenReturn(ImmutableMap.of());
        mockRequest(url);

        interceptor.process(request, context);

        verify(request).setHeaders(new Header[]{});
        verify(signer).getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMapOf(String.class, Object.class), any(com.google.common.base.Optional.class));
    }

    @Test
    public void queryParamsSupportValuesWithAmpersand() throws Exception {
        final String valueWithAmpersand = "a & b";
        final String encodedValue = SdkHttpUtils.urlEncode(valueWithAmpersand, false);
        final String url = "http://someurl.com?a=" + encodedValue + "&c=d";
        final Multimap<String, String> queryParams = ImmutableListMultimap.of("a", valueWithAmpersand, "c", "d");

        when(signer.getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMapOf(String.class, Object.class), any(com.google.common.base.Optional.class))).thenReturn(ImmutableMap.of());
        mockRequest(url);

        interceptor.process(request, context);

        verify(request).setHeaders(new Header[]{});
        verify(signer).getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMapOf(String.class, Object.class), any(com.google.common.base.Optional.class));
    }


    @Test
    public void queryParamsSupportValuesWithEquals() throws Exception {
        final String key = "scroll_id";
        final String value = "c2NhbjsxOzc3Mjo5WGljUUFNeVJGcVdDSzBjaUVQcDJ3OzE7dG90YWxfaGl0czo1NTg0Ow==";
        final String url = "http://someurl.com?" + key + "=" + value;
        final Multimap<String, String> queryParams = ImmutableListMultimap.of(key, value);

        when(signer.getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMapOf(String.class, Object.class), any(com.google.common.base.Optional.class))).thenReturn(ImmutableMap.of());
        mockRequest(url);

        interceptor.process(request, context);

        verify(request).setHeaders(new Header[]{});
        verify(signer).getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMapOf(String.class, Object.class), any(com.google.common.base.Optional.class));
    }

    @Test
    public void queryParamsSupportValuesWithoutEquals() throws Exception {
        final String key = "scroll_id";
        final String url = "http://someurl.com?" + key;
        final Multimap<String, String> queryParams = ImmutableListMultimap.of(key, "");

        when(signer.getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMapOf(String.class, Object.class), any(com.google.common.base.Optional.class))).thenReturn(ImmutableMap.of());
        mockRequest(url);

        interceptor.process(request, context);

        verify(request).setHeaders(new Header[]{});
        verify(signer).getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMapOf(String.class, Object.class), any(com.google.common.base.Optional.class));
    }

    @Test
    public void queryParamsSupportEmptyValues() throws Exception {
        final String key = "a";
        final String url = "http://someurl.com?" + key + "=";
        final Multimap<String, String> queryParams = ImmutableListMultimap.of(key, "");

        when(signer.getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMapOf(String.class, Object.class), any(com.google.common.base.Optional.class))).thenReturn(ImmutableMap.of());
        mockRequest(url);

        interceptor.process(request, context);

        verify(request).setHeaders(new Header[]{});
        verify(signer).getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMapOf(String.class, Object.class), any(com.google.common.base.Optional.class));
    }

    @Test
    public void emptyQueryParams() throws Exception {
        final String key = "a";
        final String value = "b";
        final String url = "http://someurl.com?" + key + "=" + value + "&";
        final Multimap<String, String> queryParams = ImmutableListMultimap.of(key, value);

        when(signer.getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMapOf(String.class, Object.class), any(com.google.common.base.Optional.class))).thenReturn(ImmutableMap.of());
        mockRequest(url);

        interceptor.process(request, context);

        verify(request).setHeaders(new Header[]{});
        verify(signer).getSignedHeaders(anyString(), anyString(), eq(queryParams), anyMapOf(String.class, Object.class), any(com.google.common.base.Optional.class));
    }

    private void mockRequest(String url) throws Exception {
        when(request.getURI()).thenReturn(new URI(url));
        when(request.getRequestLine()).thenReturn(new BasicRequestLine("GET", url, new ProtocolVersion("HTTP", 1, 1)));
        when(request.getAllHeaders()).thenReturn(new Header[]{});
        when(request.getOriginal()).thenReturn(request);
    }
}
