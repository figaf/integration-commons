package com.figaf.integration.common.client;

import com.figaf.integration.common.entity.RestTemplateWrapper;
import com.figaf.integration.common.factory.HttpClientsFactory;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.client.HttpClient;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author Arsenii Istlentev
 */
@Slf4j
public class RestTemplateWrapperHelper {

    private static final Map<String, RestTemplateWrapper> keyToRestTemplateWrapperMap = new ConcurrentHashMap<>();

    private static final Map<String, RestTemplateWrapper> keyToRestTemplateWrapperWithInterceptorsMap = new ConcurrentHashMap<>();

    private final HttpClientsFactory httpClientsFactory;

    public RestTemplateWrapperHelper(HttpClientsFactory httpClientsFactory) {
        this.httpClientsFactory = httpClientsFactory;
    }

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


    public RestTemplateWrapper getOrCreateRestTemplateWrapperSingleton(String key) {
        RestTemplateWrapper restTemplateWrapper = keyToRestTemplateWrapperMap.computeIfAbsent(key, k -> createRestTemplateWrapper());
        return restTemplateWrapper;
    }

    public RestTemplateWrapper createNewRestTemplateWrapper(String key) {
        RestTemplateWrapper restTemplateWrapper = createRestTemplateWrapper();
        keyToRestTemplateWrapperMap.put(key, restTemplateWrapper);
        return restTemplateWrapper;
    }

    public RestTemplateWrapper getOrCreateRestTemplateWrapperSingletonWithInterceptors(
        String key,
        Collection<ClientHttpRequestInterceptor> clientHttpRequestInterceptors
    ) {
        return keyToRestTemplateWrapperWithInterceptorsMap.computeIfAbsent(
            key,
            k -> createRestTemplateWrapper(clientHttpRequestInterceptors)
        );
    }

    public RestTemplateWrapper createNewRestTemplateWrapperWithInterceptors(
        String key,
        Collection<ClientHttpRequestInterceptor> clientHttpRequestInterceptors
    ) {
        RestTemplateWrapper restTemplateWrapper = createRestTemplateWrapper(clientHttpRequestInterceptors);
        keyToRestTemplateWrapperWithInterceptorsMap.put(key, restTemplateWrapper);
        return restTemplateWrapper;
    }

}
