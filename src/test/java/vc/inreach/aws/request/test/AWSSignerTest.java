package vc.inreach.aws.request.test;

import static org.assertj.core.api.Assertions.assertThat;
import static java.lang.String.format;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import vc.inreach.aws.request.AWSSigner;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.internal.StaticCredentialsProvider;
import com.google.common.base.Optional;
import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableMap;

public class AWSSignerTest {
    /**
     * Test case given in AWS Signing Test Suite (http://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html)
     * (get-vanilla-query.*)
     * 
     * @throws Exception
     */
    @Test
    public void testGetVanilla() throws Exception {
        // GIVEN
        // Credentials
        String awsAccessKey = "AKIDEXAMPLE";
        String awsSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        String region = "us-east-1";
        String service = "host";
        AWSCredentials credentials = new BasicAWSCredentials(awsAccessKey, awsSecretKey);
        AWSCredentialsProvider awsCredentialsProvider = new StaticCredentialsProvider(credentials);
        
        // HTTP request
        String host = "host.foo.com";
        String uri = "/";
        String method = "GET";
        
        // Date
        Supplier<LocalDateTime> clock = () -> LocalDateTime.of(2011, 9, 9, 23, 36, 0);
        // weird date : 09 Sep 2011 is a friday, not a monday
        String date = "Mon, 09 Sep 2011 23:36:00 GMT";

        // WHEN
        // The request is signed
        AWSSigner signer = new AWSSigner(awsCredentialsProvider, region, service, clock);
        Map<String, String> queryParams = new HashMap<>();
        Map<String, Object> headers = ImmutableMap.<String, Object> builder()
                .put("Date", date)
                .put("Host", host)
                .build();
        Optional<byte[]> payload = Optional.absent();
        Map<String, Object> signedHeaders = signer.getSignedHeaders(uri, method, queryParams, headers, payload);

        // THEN
        // The signature must match the expected signature
        String expectedSignature = "b27ccfbfa7df52a200ff74193ca6e32d4b48b8856fab7ebf1c595d0670a7e470";
        String expectedAuthorizationHeader = format(
                "AWS4-HMAC-SHA256 Credential=%s/20110909/%s/%s/aws4_request, SignedHeaders=date;host, Signature=%s",
                awsAccessKey, region, service, expectedSignature
                );
        
        assertThat(signedHeaders).containsKey("Authorization");
        assertThat(signedHeaders.get("Authorization")).isEqualTo(expectedAuthorizationHeader);
        assertThat(signedHeaders).containsKey("Host");
        assertThat(signedHeaders.get("Host")).isEqualTo(host);
        assertThat(signedHeaders).containsKey("Date");
        assertThat(signedHeaders.get("Date")).isEqualTo(date);
        assertThat(signedHeaders).doesNotContainKey("X-Amz-Date");
    }
}