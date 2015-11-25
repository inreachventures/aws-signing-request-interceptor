package vc.inreach.aws.request.test;

import static org.assertj.core.api.Assertions.assertThat;
import static java.lang.String.format;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.TreeMap;

import org.junit.Test;

import vc.inreach.aws.request.AWSSigner;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.internal.StaticCredentialsProvider;
import com.google.common.base.Optional;
import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableMap;

public class AWSSignerTest {
    /**
     * Test case given in AWS Signing Test Suite (http://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html)
     * (get-vanilla.*)
     * 
     * GET / http/1.1
     * Date:Mon, 09 Sep 2011 23:36:00 GMT
     * Host:host.foo.com
     * 
     * @throws Exception
     */
    @Test
    public void testGetVanilla() throws Exception {
        // GIVEN
        // Credentials
        String awsAccessKey = "AKIDEXAMPLE";
        String awsSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        AWSCredentials credentials = new BasicAWSCredentials(awsAccessKey, awsSecretKey);
        AWSCredentialsProvider awsCredentialsProvider = new StaticCredentialsProvider(credentials);
        String region = "us-east-1";
        String service = "host";
        
        // Date
        Supplier<LocalDateTime> clock = () -> LocalDateTime.of(2011, 9, 9, 23, 36, 0);
        // weird date : 09 Sep 2011 is a friday, not a monday
        String date = "Mon, 09 Sep 2011 23:36:00 GMT";
        
        // HTTP request
        String host = "host.foo.com";
        String uri = "/";
        String method = "GET";
        Map<String, String> queryParams = ImmutableMap.<String, String> builder()
                .build();
        Map<String, Object> headers = ImmutableMap.<String, Object> builder()
                .put("Date", date)
                .put("Host", host)
                .build();
        Optional<byte[]> payload = Optional.absent();

        // WHEN
        // The request is signed
        AWSSigner signer = new AWSSigner(awsCredentialsProvider, region, service, clock);
        Map<String, Object> signedHeaders = signer.getSignedHeaders(uri, method, queryParams, headers, payload);

        // THEN
        // The signature must match the expected signature
        String expectedSignature = "b27ccfbfa7df52a200ff74193ca6e32d4b48b8856fab7ebf1c595d0670a7e470";
        String expectedAuthorizationHeader = format(
                "AWS4-HMAC-SHA256 Credential=%s/20110909/%s/%s/aws4_request, SignedHeaders=date;host, Signature=%s",
                awsAccessKey, region, service, expectedSignature
                );
        
        TreeMap<String, Object> caseInsensitiveSignedHeaders = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        caseInsensitiveSignedHeaders.putAll(signedHeaders);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Authorization");
        assertThat(caseInsensitiveSignedHeaders.get("Authorization")).isEqualTo(expectedAuthorizationHeader);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Host");
        assertThat(caseInsensitiveSignedHeaders.get("Host")).isEqualTo(host);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Date");
        assertThat(caseInsensitiveSignedHeaders.get("Date")).isEqualTo(date);
        assertThat(caseInsensitiveSignedHeaders).doesNotContainKey("X-Amz-Date");
    }
    /**
     * Test case given in AWS Signing Test Suite (http://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html)
     * (post-vanilla-query.*)
     * 
     * POST /?foo=bar http/1.1
     * Date:Mon, 09 Sep 2011 23:36:00 GMT
     * Host:host.foo.com
     * 
     * @throws Exception
     */
    @Test
    public void testPostVanillaQuery() throws Exception {
        // GIVEN
        // Credentials
        String awsAccessKey = "AKIDEXAMPLE";
        String awsSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        AWSCredentials credentials = new BasicAWSCredentials(awsAccessKey, awsSecretKey);
        AWSCredentialsProvider awsCredentialsProvider = new StaticCredentialsProvider(credentials);
        String region = "us-east-1";
        String service = "host";
        
        // Date
        Supplier<LocalDateTime> clock = () -> LocalDateTime.of(2011, 9, 9, 23, 36, 0);
        // weird date : 09 Sep 2011 is a friday, not a monday
        String date = "Mon, 09 Sep 2011 23:36:00 GMT";
        
        // HTTP request
        String host = "host.foo.com";
        String uri = "/";
        String method = "POST";
        Map<String, String> queryParams = ImmutableMap.<String, String> builder()
                .put("foo", "bar")
                .build();
        Map<String, Object> headers = ImmutableMap.<String, Object> builder()
                .put("Date", date)
                .put("Host", host)
                .build();
        Optional<byte[]> payload = Optional.absent();

        // WHEN
        // The request is signed
        AWSSigner signer = new AWSSigner(awsCredentialsProvider, region, service, clock);
        Map<String, Object> signedHeaders = signer.getSignedHeaders(uri, method, queryParams, headers, payload);

        // THEN
        // The signature must match the expected signature
        String expectedSignature = "b6e3b79003ce0743a491606ba1035a804593b0efb1e20a11cba83f8c25a57a92";
        String expectedAuthorizationHeader = format(
                "AWS4-HMAC-SHA256 Credential=%s/20110909/%s/%s/aws4_request, SignedHeaders=date;host, Signature=%s",
                awsAccessKey, region, service, expectedSignature
                );
        
        TreeMap<String, Object> caseInsensitiveSignedHeaders = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        caseInsensitiveSignedHeaders.putAll(signedHeaders);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Authorization");
        assertThat(caseInsensitiveSignedHeaders.get("Authorization")).isEqualTo(expectedAuthorizationHeader);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Host");
        assertThat(caseInsensitiveSignedHeaders.get("Host")).isEqualTo(host);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Date");
        assertThat(caseInsensitiveSignedHeaders.get("Date")).isEqualTo(date);
        assertThat(caseInsensitiveSignedHeaders).doesNotContainKey("X-Amz-Date");
    }
    
    @Test
    public void testGetVanillaWithoutDateHeader() throws Exception {
        // GIVEN
        // Credentials
        String awsAccessKey = "AKIDEXAMPLE";
        String awsSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        AWSCredentials credentials = new BasicAWSCredentials(awsAccessKey, awsSecretKey);
        AWSCredentialsProvider awsCredentialsProvider = new StaticCredentialsProvider(credentials);
        String region = "us-east-1";
        String service = "host";
        
        // Date
        Supplier<LocalDateTime> clock = () -> LocalDateTime.of(2011, 9, 9, 23, 36, 0);
        // weird date : 09 Sep 2011 is a friday, not a monday
        String date = "20110909T233600Z";
        
        // HTTP request
        String host = "host.foo.com";
        String uri = "/";
        String method = "GET";
        Map<String, String> queryParams = ImmutableMap.<String, String> builder()
                .build();
        Map<String, Object> headers = ImmutableMap.<String, Object> builder()
                .put("Host", host)
                .build();
        Optional<byte[]> payload = Optional.absent();

        // WHEN
        // The request is signed
        AWSSigner signer = new AWSSigner(awsCredentialsProvider, region, service, clock);
        Map<String, Object> signedHeaders = signer.getSignedHeaders(uri, method, queryParams, headers, payload);

        // THEN
        // The signature must match the expected signature
        String expectedSignature = "904f8c568bca8bd2618b9241a7f2a8d90f279e717fd0f6727af189668b040151";
        String expectedAuthorizationHeader = format(
                "AWS4-HMAC-SHA256 Credential=%s/20110909/%s/%s/aws4_request, SignedHeaders=host;x-amz-date, Signature=%s",
                awsAccessKey, region, service, expectedSignature
                );
        
        TreeMap<String, Object> caseInsensitiveSignedHeaders = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        caseInsensitiveSignedHeaders.putAll(signedHeaders);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Authorization");
        assertThat(caseInsensitiveSignedHeaders.get("Authorization")).isEqualTo(expectedAuthorizationHeader);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Host");
        assertThat(caseInsensitiveSignedHeaders.get("Host")).isEqualTo(host);
        assertThat(caseInsensitiveSignedHeaders).containsKey("X-Amz-Date");
        assertThat(caseInsensitiveSignedHeaders.get("X-Amz-Date")).isEqualTo(date);
        assertThat(caseInsensitiveSignedHeaders).doesNotContainKey("Date");
    }
    
    @Test
    public void testGetVanillaWithTempCreds() throws Exception {
        // GIVEN
        // Credentials
        String awsAccessKey = "AKIDEXAMPLE";
        String awsSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        String sessionToken = "AKIDEXAMPLESESSION";
        AWSCredentials credentials = new BasicSessionCredentials(awsAccessKey, awsSecretKey, sessionToken);
        AWSCredentialsProvider awsCredentialsProvider = new StaticCredentialsProvider(credentials);
        String region = "us-east-1";
        String service = "host";
        
        // Date
        Supplier<LocalDateTime> clock = () -> LocalDateTime.of(2011, 9, 9, 23, 36, 0);
        // weird date : 09 Sep 2011 is a friday, not a monday
        String date = "Mon, 09 Sep 2011 23:36:00 GMT";
        
        // HTTP request
        String host = "host.foo.com";
        String uri = "/";
        String method = "GET";
        Map<String, String> queryParams = ImmutableMap.<String, String> builder()
                .build();
        Map<String, Object> headers = ImmutableMap.<String, Object> builder()
                .put("Date", date)
                .put("Host", host)
                .build();
        Optional<byte[]> payload = Optional.absent();

        // WHEN
        // The request is signed
        AWSSigner signer = new AWSSigner(awsCredentialsProvider, region, service, clock);
        Map<String, Object> signedHeaders = signer.getSignedHeaders(uri, method, queryParams, headers, payload);

        // THEN
        // The signature must match the expected signature
        String expectedSignature = "43abd9e63c148feb91c43fe2c9734eb44b7eb16078d484d3ff9b6249b62fdc60";
        String expectedAuthorizationHeader = format(
                "AWS4-HMAC-SHA256 Credential=%s/20110909/%s/%s/aws4_request, SignedHeaders=date;host;x-amz-security-token, Signature=%s",
                awsAccessKey, region, service, expectedSignature
                );
        
        TreeMap<String, Object> caseInsensitiveSignedHeaders = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        caseInsensitiveSignedHeaders.putAll(signedHeaders);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Authorization");
        assertThat(caseInsensitiveSignedHeaders.get("Authorization")).isEqualTo(expectedAuthorizationHeader);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Host");
        assertThat(caseInsensitiveSignedHeaders.get("Host")).isEqualTo(host);
        assertThat(caseInsensitiveSignedHeaders).containsKey("Date");
        assertThat(caseInsensitiveSignedHeaders.get("Date")).isEqualTo(date);
        assertThat(caseInsensitiveSignedHeaders).doesNotContainKey("X-Amz-Date");
        assertThat(caseInsensitiveSignedHeaders).containsKey("X-Amz-Security-Token");
        assertThat(caseInsensitiveSignedHeaders.get("X-Amz-Security-Token")).isEqualTo(sessionToken);
    }
}
