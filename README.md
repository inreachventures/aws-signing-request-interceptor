aws-signing-request-interceptor
===

Request Interceptor for Apache Client that signs the request for AWS. 

Originally created to support AWS' [Elasticsearch Service](https://aws.amazon.com/elasticsearch-service/) using the [Jest client](https://github.com/searchbox-io/Jest).

Usage
-----

You have to add the AWSSigningRequestInterceptor to the end of the Apache client request chain. Otherwise it won't have visibility of all of the headers being added to the request.

This depends on the AWS core SDK as it relies on an AWSCredentialsProvider to get the key, secret and optional session token. It's advised that you use dependencyManagement to lock in the version of `aws-java-sdk-core` that works for your project.


```java
private static final String SERVICE = "es";
private static final String REGION = "eu-west-1";
...
final AWSSigner awsSigner = new AWSSigner(awsCredentialsProvider, REGION, SERVICE, clock);
builder.addInterceptorLast(new AWSSigningRequestInterceptor(awsSigner));
```

To be able to add the AWSSigningRequestInterceptor to Jest, and thus be able to sign requests to the Elasticsearch Service, you need to override the `configureHttpClient` method in the `JestClientFactory`.

```java
final AWSSigningRequestInterceptor requestInterceptor = new AWSSigningRequestInterceptor(awsSigner);
final JestClientFactory factory = new JestClientFactory() {
    @Override
    protected HttpClientBuilder configureHttpClient(HttpClientBuilder builder) {
        builder.addInterceptorLast(requestInterceptor);
        return builder;
    }
    @Override
    protected HttpAsyncClientBuilder configureHttpClient(HttpAsyncClientBuilder builder) {
        builder.addInterceptorLast(requestInterceptor);
        return builder;
    }
};
```

The project can be found in maven central:

```xml
<dependency>
    <groupId>vc.inreach.aws</groupId>
    <artifactId>aws-signing-request-interceptor</artifactId>
    <version>0.0.11</version>
</dependency>
```

Other Languages
---------------

If you're looking for a native Scala version of the AWSSigner then take a look at [@ticofab](https://github.com/ticofab/)'s port: https://github.com/ticofab/aws-request-signer
