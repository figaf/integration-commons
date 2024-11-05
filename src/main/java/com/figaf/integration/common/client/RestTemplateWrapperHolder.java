package com.figaf.integration.common.client;

import com.figaf.integration.common.entity.RequestContext;
import com.figaf.integration.common.entity.RestTemplateWrapper;
import com.figaf.integration.common.factory.RestTemplateWrapperFactory;
import com.figaf.integration.common.utils.HttpClientUtils;
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

    public RestTemplateWrapper getOrCreateRestTemplateWrapperSingleton(RequestContext requestContext) {
        RestTemplateWrapper restTemplateWrapper = keyToRestTemplateWrapperMap.computeIfAbsent(
            requestContext.getRestTemplateWrapperKey(),
            k -> restTemplateWrapperFactory.createRestTemplateWrapper(requestContext)
        );
        return restTemplateWrapper;
    }

    public RestTemplateWrapper createNewRestTemplateWrapper(RequestContext requestContext) {
        RestTemplateWrapper restTemplateWrapper = restTemplateWrapperFactory.createRestTemplateWrapper(requestContext);
        keyToRestTemplateWrapperMap.put(requestContext.getRestTemplateWrapperKey(), restTemplateWrapper);
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
        RestTemplateWrapper wrapperToRemove = keyToRestTemplateWrapperMap.remove(key);
        if (wrapperToRemove != null) {
            HttpClientUtils.closeQuietly(wrapperToRemove.getHttpClient());
        }
    }

    public static void deleteRestTemplateWrapperSingletonWithInterceptors(String key) {
        RestTemplateWrapper wrapperToRemove = keyToRestTemplateWrapperWithInterceptorsMap.remove(key);
        if (wrapperToRemove != null) {
            HttpClientUtils.closeQuietly(wrapperToRemove.getHttpClient());
        }
    }

}
