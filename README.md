aws-signing-request-interceptor
===

Request Interceptor for Apache Client that signs the request for AWS. 

Originally created to support AWS' [Elasticsearch Service](https://aws.amazon.com/elasticsearch-service/) using the [Jest client](https://github.com/searchbox-io/Jest).

Usage
-----

You have to add the AWSSigningRequestInterceptor to the end of the Apache client request chain. Otherwise it won't have visibility of all of the headers being added to the request.

```java
final AWSSigner awsSigner = new AWSSigner(awsKey, awsSecret, REGION, SERVICE, clock);
builder.addInterceptorLast(new AWSSigningRequestInterceptor(awsSigner));
```

To be able to add the AWSSigningRequestInterceptor to Jest, and thus be able to sign requests to the Elasticsearch Service, you need to override the `configureHttpClient` method in the `JestClientFactory`.

```java
final JestClientFactory factory = new JestClientFactory() {
    @Override
    protected HttpClientBuilder configureHttpClient(HttpClientBuilder builder) {
        builder.addInterceptorLast(new AWSSigningRequestInterceptor(awsSigner));
        return builder;
    }
};
```

The project can be found in maven central:

```xml
<dependency>
    <groupId>vc.inreach.aws</groupId>
    <artifactId>aws-signing-request-interceptor</artifactId>
    <version>0.0.2</version>
</dependency>
```

TODO
----

* Write tests
* Allow different credential providers (maybe. it's quite nice not having to depend on an AWS SDK)
