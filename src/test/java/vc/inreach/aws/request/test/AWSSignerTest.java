package vc.inreach.aws.request.test;

import static org.assertj.core.api.Assertions.assertThat;

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
    @Test
    public void testGetVanilla() throws Exception {
        // GIVEN
        String awsAccessKey = "AKIDEXAMPLE";
        String awsSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        String region = "us-east-1";
        String service = "host";
        Supplier<LocalDateTime> clock = () -> LocalDateTime.of(2011, 9, 9, 23, 36, 0);
        AWSCredentials credentials = new BasicAWSCredentials(awsAccessKey, awsSecretKey);
        AWSCredentialsProvider awsCredentialsProvider = new StaticCredentialsProvider(credentials);

        // WHEN
        AWSSigner signer = new AWSSigner(awsCredentialsProvider, region, service, clock);
        String uri = "/";
        String method = "GET";
        Map<String, String> queryParams = new HashMap<>();
        Map<String, Object> headers = ImmutableMap.<String, Object> builder()
                .put("Date", "Mon, 09 Sep 2011 23:36:00 GMT")
                .put("Host", "host.foo.com")
                .build();
        Optional<byte[]> payload = Optional.absent();
        Map<String, Object> signedHeaders = signer.getSignedHeaders(uri, method, queryParams, headers, payload);

        // THEN
        assertThat(signedHeaders)
                .containsKey("Authorization");
        assertThat(signedHeaders.get("Authorization"))
                .isEqualTo(
                        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host, Signature=b27ccfbfa7df52a200ff74193ca6e32d4b48b8856fab7ebf1c595d0670a7e470");
    }
}
