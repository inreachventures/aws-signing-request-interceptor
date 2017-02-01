package vc.inreach.aws.request.test;
import com.amazonaws.DefaultRequest;
import com.amazonaws.auth.AWS4Signer;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.http.HttpMethodName;
import com.amazonaws.util.StringInputStream;
import com.google.common.collect.Multimap;

import java.lang.reflect.Method;
import java.net.URI;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
/**
 * Test utility used to generate a AWS V4 Signature using {@link com.amazonaws.auth.AWS4Signer}.  This is needed in cases where the
 * the AWS Signing Test Suite (http://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html) does not include
 * a suitable test.
 */
public class SkdSignerUtil {

    static public String getExpectedAuthorizationHeader(Request request) throws Exception {
        // create the signable request
        DefaultRequest signableRequest = new DefaultRequest(null, request.getServiceName());
        signableRequest.setEndpoint(new URI("http://" + request.getHost()));
        signableRequest.setResourcePath(request.getUri());
        signableRequest.setHttpMethod(HttpMethodName.valueOf(request.getHttpMethod()));
        signableRequest.setContent(new StringInputStream(request.getBody()));
        if (request.getHeaders() != null)
            signableRequest.setHeaders(request.getHeaders());
        if (request.getQueryParams() != null) {
            Map<String, List<String>> convertedQueryParams = new HashMap<>();
            for (String paramName : request.getQueryParams().keySet()) {
                convertedQueryParams.put(paramName, new ArrayList<>(request.getQueryParams().get(paramName)));
            }
            signableRequest.setParameters(convertedQueryParams);
        }

        /*
           Init the signer class

           Note: Double uri encoding is off simple before the signature does not match the expected signature of the test cases
           if it is enabled.  This was a bit unexpected because AWSElasticsearchClient (AWS SDK Class) enabled double URI encoding
           in the signer by default.  I can only assume that double encoding is needed when accessing the service but not when accessing
           elasticsearch.
         */
        AWS4Signer aws4Signer = new AWS4Signer(false);
        aws4Signer.setServiceName(request.getServiceName());
        aws4Signer.setRegionName(request.getRegion());
        Method method1 = AWS4Signer.class.getDeclaredMethod("setOverrideDate", Date.class);
        method1.setAccessible(true);
        method1.invoke(aws4Signer, request.getDate());
        aws4Signer.sign(signableRequest, request.getCredentialsProvider().getCredentials());

        return (String) signableRequest.getHeaders().get("Authorization");
    }

    /**
     * Represents a request to be signed
     */
    static class Request {
        private String serviceName;
        private String region;
        private Date date;
        private String host;
        private String uri;
        private String body = "";
        private String httpMethod;
        private Map<String, Object> headers;
        private Multimap<String, String> queryParams;
        private AWSCredentialsProvider credentialsProvider;

        public String getServiceName() {
            return serviceName;
        }
        public Request setServiceName(String serviceName) {
            this.serviceName = serviceName;
            return this;
        }
        public String getRegion() {
            return region;
        }
        public Request setRegion(String region) {
            this.region = region;
            return this;
        }
        public Date getDate() {
            return date;
        }
        public Request setDate(Date date) {
            this.date = date;
            return this;
        }
        public String getHost() {
            return host;
        }
        public Request setHost(String host) {
            this.host = host;
            return this;
        }
        public String getUri() {
            return uri;
        }
        public Request setUri(String uri) {
            this.uri = uri;
            return this;
        }
        public String getBody() {
            return body;
        }
        public Request setBody(String body) {
            this.body = body;
            return this;
        }
        public String getHttpMethod() {
            return httpMethod;
        }
        public Request setHttpMethod(String httpMethod) {
            this.httpMethod = httpMethod;
            return this;
        }
        public Map<String, Object> getHeaders() {
            return headers;
        }
        public Request setHeaders(Map<String, Object> headers) {
            this.headers = headers;
            return this;
        }
        public Multimap<String, String> getQueryParams() {
            return queryParams;
        }
        public Request setQueryParams(Multimap<String, String> queryParams) {
            this.queryParams = queryParams;
            return this;
        }
        public AWSCredentialsProvider getCredentialsProvider() {
            return credentialsProvider;
        }
        public Request setCredentialsProvider(AWSCredentialsProvider credentialsProvider) {
            this.credentialsProvider = credentialsProvider;
            return this;
        }
    }

}
