package vc.inreach.aws.request;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.TreeMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.joda.time.LocalDateTime;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.DateTimeFormatterBuilder;
import org.joda.time.format.ISODateTimeFormat;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.google.common.base.Charsets;
import com.google.common.base.Joiner;
import com.google.common.base.Optional;
import com.google.common.base.Supplier;
import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

/**
 * Inspired By: http://pokusak.blogspot.co.uk/2015/10/aws-elasticsearch-request-signing.html
 */
public class AWSSigner {

    private final static char[] BASE16MAP = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    private static final String HMAC_SHA256 = "HmacSHA256";
    private static final String SLASH = "/";
    private static final String X_AMZ_DATE = "x-amz-date";
    private static final String RETURN = "\n";
    private static final String AWS4_HMAC_SHA256 = "AWS4-HMAC-SHA256\n";
    private static final String AWS4_REQUEST = "/aws4_request";
    private static final String AWS4_HMAC_SHA256_CREDENTIAL = "AWS4-HMAC-SHA256 Credential=";
    private static final String SIGNED_HEADERS = ", SignedHeaders=";
    private static final String SIGNATURE = ", Signature=";
    private static final String SHA_256 = "SHA-256";
    private static final String AWS4 = "AWS4";
    private static final String AWS_4_REQUEST = "aws4_request";
    private static final Joiner JOINER = Joiner.on(';');
    private static final String CONNECTION = "connection";
    private static final String CLOSE = ":close";
    private static final DateTimeFormatter BASIC_TIME_FORMAT = new DateTimeFormatterBuilder()
            .appendYear(4, 4)
            .appendMonthOfYear(2)
            .appendDayOfMonth(2)
            .appendLiteral('T')
            .appendHourOfDay(2)
            .appendMinuteOfHour(2)
            .appendSecondOfMinute(2)
            .appendLiteral('Z')
            .toFormatter();
    private static final String EMPTY = "";
    private static final String ZERO = "0";
    private static final Joiner AMPERSAND_JOINER = Joiner.on('&');
    private static final String CONTENT_LENGTH = "Content-Length";
    private static final String AUTHORIZATION = "Authorization";

    private final AWSCredentialsProvider awsCredentialsProvider;
    private final String region;
    private final String service;
    private final Supplier<LocalDateTime> clock;

    public AWSSigner(AWSCredentialsProvider awsCredentialsProvider, String region, String service, Supplier<LocalDateTime> clock) {
        this.awsCredentialsProvider = awsCredentialsProvider;
        this.region = region;
        this.service = service;
        this.clock = clock;
    }

    public Map<String, Object> getSignedHeaders(String uri, String method, Map<String, String> queryParams, Map<String, Object> headers, Optional<byte[]> payload) {
        final LocalDateTime now = clock.get();
        final ImmutableMap.Builder<String, Object> result = ImmutableMap.builder();
        result.putAll(headers);
        result.put(X_AMZ_DATE, BASIC_TIME_FORMAT.print(now));

        final StringBuilder headersString = new StringBuilder();
        final ImmutableList.Builder<String> signedHeaders = ImmutableList.builder();

        for (Map.Entry<String, Object> entry : new TreeMap<>(result.build()).entrySet()) {
            headersString.append(headerAsString(entry)).append(RETURN);
            signedHeaders.add(entry.getKey().toLowerCase());
        }

        final String signedHeaderKeys = JOINER.join(signedHeaders.build());
        final String canonicalRequest = method + RETURN +
                uri + RETURN +
                queryParamsString(queryParams) + RETURN +
                headersString.toString() + RETURN +
                signedHeaderKeys + RETURN +
                toBase16(hash(payload.or(EMPTY.getBytes(Charsets.UTF_8))));
        final String stringToSign = createStringToSign(canonicalRequest, now);
        final String signature = sign(stringToSign, now);
        String awsAccessKeyId = awsCredentialsProvider.getCredentials().getAWSAccessKeyId();
        final String autorizationHeader = AWS4_HMAC_SHA256_CREDENTIAL + awsAccessKeyId + SLASH + getCredentialScope(now) +
                SIGNED_HEADERS + signedHeaderKeys +
                SIGNATURE + signature;

        result.put(AUTHORIZATION, autorizationHeader);
        return result.build();
    }

    private String queryParamsString(Map<String, String> queryParams) {
        final ImmutableList.Builder<String> result = ImmutableList.builder();

        for (Map.Entry<String, String> param : new TreeMap<>(queryParams).entrySet()) {
            result.add(param.getKey() + '=' + param.getValue());
        }

        return AMPERSAND_JOINER.join(result.build());
    }

    private String headerAsString(Map.Entry<String, Object> header) {
        if (header.getKey().equalsIgnoreCase(CONNECTION)) {
            return CONNECTION + CLOSE;
        }
        if (header.getKey().equalsIgnoreCase(CONTENT_LENGTH) &&
                header.getValue().equals(ZERO)) {
            return header.getKey().toLowerCase() + ':';
        }
        return header.getKey().toLowerCase() + ':' + header.getValue();
    }

    private String sign(String stringToSign, LocalDateTime now) {
        return Hex.encodeHexString(hmacSHA256(stringToSign, getSignatureKey(now)));
    }

    private String createStringToSign(String canonicalRequest, LocalDateTime now) {
        return AWS4_HMAC_SHA256 +
                BASIC_TIME_FORMAT.print(now) + RETURN +
                getCredentialScope(now) + RETURN +
                toBase16(hash(canonicalRequest.getBytes(Charsets.UTF_8)));
    }

    private String getCredentialScope(LocalDateTime now) {
        return ISODateTimeFormat.basicDate().print(now) + SLASH + region + SLASH + service + AWS4_REQUEST;
    }

    private byte[] hash(byte[] payload) {
        try {
            final MessageDigest md = MessageDigest.getInstance(SHA_256);
            md.update(payload);
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw Throwables.propagate(e);
        }
    }

    private String toBase16(byte[] data) {
        final StringBuilder hexBuffer = new StringBuilder(data.length * 2);
        for (byte aData : data) {
            hexBuffer.append(BASE16MAP[(aData >> (4)) & 0xF]);
            hexBuffer.append(BASE16MAP[(aData) & 0xF]);
        }
        return hexBuffer.toString();
    }

    private byte[] getSignatureKey(LocalDateTime now) {
        String awsSecretKey = awsCredentialsProvider.getCredentials().getAWSSecretKey();
        final byte[] kSecret = (AWS4 + awsSecretKey).getBytes(Charsets.UTF_8);
        final byte[] kDate = hmacSHA256(ISODateTimeFormat.basicDate().print(now), kSecret);
        final byte[] kRegion = hmacSHA256(region, kDate);
        final byte[] kService = hmacSHA256(service, kRegion);
        return hmacSHA256(AWS_4_REQUEST, kService);
    }

    private byte[] hmacSHA256(String data, byte[] key) {
        try {
            final Mac mac = Mac.getInstance(HMAC_SHA256);
            mac.init(new SecretKeySpec(key, HMAC_SHA256));
            return mac.doFinal(data.getBytes(Charsets.UTF_8));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw Throwables.propagate(e);
        }
    }
}
