package com.figaf.integration.common.factory;

import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpUriRequest;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;

import java.net.URI;

/**
 * @author Arsenii Istlentev
 */
//The idea is taken from here: https://thegeekyasian.com/http-get-request-with-a-request-body-using-resttemplate/
public class CustomHttpComponentsClientHttpRequestFactory extends HttpComponentsClientHttpRequestFactory {

    public CustomHttpComponentsClientHttpRequestFactory() {
    }

    public CustomHttpComponentsClientHttpRequestFactory(HttpClient httpClient) {
        super(httpClient);
    }

    @Override
    protected HttpUriRequest createHttpUriRequest(HttpMethod httpMethod, URI uri) {
        if (HttpMethod.GET.equals(httpMethod)) {
            return new HttpEntityEnclosingGetRequestBase(uri);
        }
        return super.createHttpUriRequest(httpMethod, uri);
    }

    private static class HttpEntityEnclosingGetRequestBase extends HttpEntityEnclosingRequestBase {

        public HttpEntityEnclosingGetRequestBase(final URI uri) {
            super.setURI(uri);
        }

        @Override
        public String getMethod() {
            return HttpMethod.GET.name();
        }

    }
}
