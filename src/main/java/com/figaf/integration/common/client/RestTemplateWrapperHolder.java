package com.figaf.integration.common.client;

import com.figaf.integration.common.entity.RestTemplateWrapper;
import com.figaf.integration.common.factory.RestTemplateWrapperFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author Arsenii Istlentev
 */
@Slf4j
public class RestTemplateWrapperHolder {

    private static final Map<String, RestTemplateWrapper> keyToRestTemplateWrapperMap = new ConcurrentHashMap<>();

    private static final Map<String, RestTemplateWrapper> keyToRestTemplateWrapperWithInterceptorsMap = new ConcurrentHashMap<>();

    private final RestTemplateWrapperFactory restTemplateWrapperFactory;

    public RestTemplateWrapperHolder(RestTemplateWrapperFactory restTemplateWrapperFactory) {
        this.restTemplateWrapperFactory = restTemplateWrapperFactory;
    }

    public RestTemplateWrapper getOrCreateRestTemplateWrapperSingleton(String key) {
        RestTemplateWrapper restTemplateWrapper = keyToRestTemplateWrapperMap.computeIfAbsent(
            key,
            k -> restTemplateWrapperFactory.createRestTemplateWrapper()
        );
        return restTemplateWrapper;
    }

    public RestTemplateWrapper createNewRestTemplateWrapper(String key) {
        RestTemplateWrapper restTemplateWrapper = restTemplateWrapperFactory.createRestTemplateWrapper();
        keyToRestTemplateWrapperMap.put(key, restTemplateWrapper);
        return restTemplateWrapper;
    }

    public RestTemplateWrapper getOrCreateRestTemplateWrapperSingletonWithInterceptors(
        String key,
        Collection<ClientHttpRequestInterceptor> clientHttpRequestInterceptors
    ) {
        return keyToRestTemplateWrapperWithInterceptorsMap.computeIfAbsent(
            key,
            k -> restTemplateWrapperFactory.createRestTemplateWrapper(clientHttpRequestInterceptors)
        );
    }

    public static void deleteRestTemplateWrapper(String key) {
        keyToRestTemplateWrapperMap.remove(key);
    }

    public static void deleteRestTemplateWrapperSingletonWithInterceptors(String key) {
        keyToRestTemplateWrapperWithInterceptorsMap.remove(key);
    }

}
