package com.figaf.integration.common.factory;

import com.figaf.integration.common.entity.RequestContext;
import com.figaf.integration.common.entity.RestTemplateWrapper;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.cookie.BasicCookieStore;
import org.apache.hc.client5.http.cookie.CookieStore;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.util.Collection;

/**
 * @author Klochkov Sergey
 */
@Slf4j
@Getter
@ToString
@AllArgsConstructor
public class RestTemplateWrapperFactory {

    private final HttpClientsFactory httpClientsFactory;

    public RestTemplateWrapper createRestTemplateWrapper() {
        return createRestTemplateWrapper(false);
    }

    public RestTemplateWrapper createRestTemplateWrapperDisablingRedirect() {
        return createRestTemplateWrapper(true);
    }


    public RestTemplateWrapper createRestTemplateWrapper(RequestContext requestContext) {
        CookieStore cookieStore = new BasicCookieStore();
        HttpComponentsClientHttpRequestFactory httpComponentsClientHttpRequestFactory = httpClientsFactory.getHttpComponentsClientHttpRequestFactory(
            requestContext,
            cookieStore
        );
        HttpClient httpClient = httpComponentsClientHttpRequestFactory.getHttpClient();
        RestTemplate restTemplate = new RestTemplate(httpComponentsClientHttpRequestFactory);
        restTemplate.getMessageConverters().add(0, new StringHttpMessageConverter(StandardCharsets.UTF_8));
        return new RestTemplateWrapper(restTemplate, httpClient, cookieStore);
    }

    public RestTemplateWrapper createRestTemplateWrapper(boolean disableRedirect) {
        CookieStore cookieStore = new BasicCookieStore();
        HttpComponentsClientHttpRequestFactory httpComponentsClientHttpRequestFactory = httpClientsFactory.getHttpComponentsClientHttpRequestFactory(
            disableRedirect,
            false,
            false,
            cookieStore
        );
        HttpClient httpClient = httpComponentsClientHttpRequestFactory.getHttpClient();
        RestTemplate restTemplate = new RestTemplate(httpComponentsClientHttpRequestFactory);
        restTemplate.getMessageConverters().add(0, new StringHttpMessageConverter(StandardCharsets.UTF_8));
        return new RestTemplateWrapper(restTemplate, httpClient, cookieStore);
    }

    public RestTemplateWrapper createRestTemplateWrapper(Collection<ClientHttpRequestInterceptor> clientHttpRequestInterceptors) {
        CookieStore cookieStore = new BasicCookieStore();
        HttpComponentsClientHttpRequestFactory httpComponentsClientHttpRequestFactory = httpClientsFactory.getHttpComponentsClientHttpRequestFactory(
            false,
            false,
            false,
            cookieStore
        );
        HttpClient httpClient = httpComponentsClientHttpRequestFactory.getHttpClient();
        RestTemplate restTemplate = new RestTemplate(httpComponentsClientHttpRequestFactory);
        restTemplate.getInterceptors().addAll(clientHttpRequestInterceptors);
        restTemplate.getMessageConverters().add(0, new StringHttpMessageConverter(StandardCharsets.UTF_8));
        return new RestTemplateWrapper(restTemplate, httpClient, null);
    }

}
