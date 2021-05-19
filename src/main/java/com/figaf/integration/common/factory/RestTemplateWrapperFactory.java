package com.figaf.integration.common.factory;

import com.figaf.integration.common.entity.RestTemplateWrapper;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.client.HttpClient;
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
        HttpComponentsClientHttpRequestFactory httpComponentsClientHttpRequestFactory = httpClientsFactory.getHttpComponentsClientHttpRequestFactory();
        HttpClient httpClient = httpComponentsClientHttpRequestFactory.getHttpClient();
        RestTemplate restTemplate = new RestTemplate(httpComponentsClientHttpRequestFactory);
        restTemplate.getMessageConverters().add(0, new StringHttpMessageConverter(StandardCharsets.UTF_8));
        return new RestTemplateWrapper(restTemplate, httpClient);
    }

    public RestTemplateWrapper createRestTemplateWrapper(Collection<ClientHttpRequestInterceptor> clientHttpRequestInterceptors) {
        HttpComponentsClientHttpRequestFactory httpComponentsClientHttpRequestFactory = httpClientsFactory.getHttpComponentsClientHttpRequestFactory();
        HttpClient httpClient = httpComponentsClientHttpRequestFactory.getHttpClient();
        RestTemplate restTemplate = new RestTemplate(httpComponentsClientHttpRequestFactory);
        restTemplate.getInterceptors().addAll(clientHttpRequestInterceptors);
        restTemplate.getMessageConverters().add(0, new StringHttpMessageConverter(StandardCharsets.UTF_8));
        return new RestTemplateWrapper(restTemplate, httpClient);
    }

}
