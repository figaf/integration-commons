package com.figaf.integration.common.client;

import com.figaf.integration.common.client.support.OAuthTokenInterceptor;
import com.figaf.integration.common.client.support.parser.CloudFoundryOAuthTokenParser;
import com.figaf.integration.common.entity.ConnectionProperties;
import com.figaf.integration.common.entity.OAuthTokenRequestContext;
import com.figaf.integration.common.entity.RequestContext;
import com.figaf.integration.common.entity.message_sender.MessageSendingAdditionalProperties;
import com.figaf.integration.common.factory.HttpClientsFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.support.BasicAuthenticationInterceptor;
import org.springframework.util.Assert;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.ArrayList;

import static java.util.Collections.singleton;
import static java.util.Collections.singletonList;

/**
 * @author Nesterov Ilya
 */
@Slf4j
public class HttpMessageSender extends MessageSender {

    private static final String X_CSRF_TOKEN = "X-CSRF-Token";

    private final CsrfTokenHolder csrfTokenHolder;

    public HttpMessageSender(HttpClientsFactory httpClientsFactory) {
        super(httpClientsFactory);
        csrfTokenHolder = new CsrfTokenHolder();
    }

    public ResponseEntity<String> sendMessageWithBasicAuthentication(
        RequestContext requestContext,
        String url,
        HttpMethod httpMethod,
        HttpEntity<byte[]> requestEntity,
        MessageSendingAdditionalProperties messageSendingAdditionalProperties
    ) {
        ConnectionProperties connectionProperties = requestContext.getConnectionPropertiesForTesting();
        RestTemplate restTemplate = restTemplateWrapperHolder.getOrCreateRestTemplateWrapperSingletonWithInterceptors(
            messageSendingAdditionalProperties.getRestTemplateWrapperKey(),
            singleton(
                new BasicAuthenticationInterceptor(connectionProperties.getUsername(), connectionProperties.getPassword())
            )
        ).getRestTemplate();
        return sendMessage(
            restTemplate,
            url,
            httpMethod,
            requestEntity,
            messageSendingAdditionalProperties
        );
    }

    public ResponseEntity<String> sendMessageWithOAuth(
        RequestContext requestContext,
        String url,
        HttpMethod httpMethod,
        HttpEntity<byte[]> requestEntity,
        MessageSendingAdditionalProperties messageSendingAdditionalProperties
    ) {
        ConnectionProperties connectionProperties = requestContext.getConnectionPropertiesForTesting();
        RestTemplate restTemplate = restTemplateWrapperHolder.getOrCreateRestTemplateWrapperSingletonWithInterceptors(
            messageSendingAdditionalProperties.getRestTemplateWrapperKey(),
            singleton(new OAuthTokenInterceptor(
                new OAuthTokenRequestContext(
                    connectionProperties.getUsername(),
                    connectionProperties.getPassword(),
                    messageSendingAdditionalProperties.getOauthUrl()
                ),
                new CloudFoundryOAuthTokenParser(),
                httpClientsFactory
            ))
        ).getRestTemplate();
        return sendMessage(
            restTemplate,
            url,
            httpMethod,
            requestEntity,
            messageSendingAdditionalProperties
        );
    }

    private ResponseEntity<String> sendMessage(
        RestTemplate restTemplate,
        String url,
        HttpMethod httpMethod,
        HttpEntity<byte[]> requestEntity,
        MessageSendingAdditionalProperties messageSendingAdditionalProperties
    ) {
        UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromHttpUrl(url);
        String uri = uriBuilder.toUriString();

        String csrfToken = null;
        if (messageSendingAdditionalProperties.isCsrfProtected()) {
            csrfToken = csrfTokenHolder.getCsrfToken(
                messageSendingAdditionalProperties.getRestTemplateWrapperKey(),
                restTemplate,
                url
            );
        }

        try {
            if (messageSendingAdditionalProperties.isRawMode()) {
                ResponseEntity<String> result = restTemplate.execute(
                    uri,
                    httpMethod,
                    createRequestCallbackWithCsrfTokenIfNeeds(
                        requestEntity,
                        csrfToken
                    ),
                    restTemplate.responseEntityExtractor(String.class)
                );
                Assert.state(result != null, "No result");
                return result;
            } else {
                return restTemplate.exchange(
                    uri,
                    httpMethod,
                    createRequestEntityWithCsrfTokenIfNeeds(
                        requestEntity,
                        csrfToken
                    ),
                    String.class
                );
            }
        } catch (HttpClientErrorException.Forbidden ex) {
            return processForbiddenHttpClientErrorException(
                ex,
                restTemplate,
                uri,
                requestEntity,
                httpMethod,
                messageSendingAdditionalProperties,
                csrfToken
            );
        }
    }

    private ResponseEntity<String> processForbiddenHttpClientErrorException(
        HttpClientErrorException.Forbidden ex,
        RestTemplate restTemplate,
        String url,
        HttpEntity<byte[]> requestEntity,
        HttpMethod httpMethod,
        MessageSendingAdditionalProperties messageSendingAdditionalProperties,
        String oldToken
    ) {
        if (ex.getResponseHeaders() != null &&
            "required".equalsIgnoreCase(ex.getResponseHeaders().getFirst(X_CSRF_TOKEN))
        ) {
            if (messageSendingAdditionalProperties.isRawMode()) {
                ResponseEntity<String> result = restTemplate.execute(
                    url,
                    httpMethod,
                    createRequestCallbackWithNewCsrfToken(
                        requestEntity,
                        restTemplate,
                        url,
                        messageSendingAdditionalProperties.getRestTemplateWrapperKey(),
                        oldToken
                    ),
                    restTemplate.responseEntityExtractor(String.class)
                );
                Assert.state(result != null, "No result");
                return result;
            } else {
                return restTemplate.exchange(
                    url,
                    httpMethod,
                    createRequestEntityWithNewCsrfToken(
                        restTemplate,
                        url,
                        requestEntity,
                        messageSendingAdditionalProperties.getRestTemplateWrapperKey(),
                        oldToken
                    ),
                    String.class
                );
            }
        } else {
            throw ex;
        }
    }

    private HttpEntity<byte[]> createRequestEntityWithCsrfTokenIfNeeds(
        HttpEntity<byte[]> requestEntity,
        String csrfToken
    ) {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.addAll(requestEntity.getHeaders());
        httpHeaders.put(X_CSRF_TOKEN, singletonList(csrfToken));
        return new HttpEntity<>(requestEntity.getBody(), httpHeaders);
    }

    private HttpEntity<byte[]> createRequestEntityWithNewCsrfToken(
        RestTemplate restTemplate,
        String url,
        HttpEntity<byte[]> requestEntity,
        String tokenKey,
        String oldToken
    ) {
        String csrfToken = csrfTokenHolder.getAndSaveNewCsrfTokenIfNeed(tokenKey, restTemplate, url, oldToken);
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.addAll(requestEntity.getHeaders());
        httpHeaders.put(X_CSRF_TOKEN, singletonList(csrfToken));
        return new HttpEntity<>(requestEntity.getBody(), httpHeaders);
    }

    private RequestCallback createRequestCallbackWithCsrfTokenIfNeeds(
        HttpEntity<byte[]> requestEntity,
        String csrfToken
    ) {
        if (csrfToken == null) {
            return createRequestCallback(requestEntity);
        }

        return request -> {
            createRequestCallback(requestEntity).doWithRequest(request);
            request.getHeaders().set(X_CSRF_TOKEN, csrfToken);
        };
    }

    private RequestCallback createRequestCallbackWithNewCsrfToken(
        HttpEntity<byte[]> requestEntity,
        RestTemplate restTemplate,
        String url,
        String tokenKey,
        String oldToken
    ) {
        String csrfToken = csrfTokenHolder.getAndSaveNewCsrfTokenIfNeed(tokenKey, restTemplate, url, oldToken);
        return request -> {
            createRequestCallback(requestEntity).doWithRequest(request);
            request.getHeaders().set(X_CSRF_TOKEN, csrfToken);
        };
    }

    private RequestCallback createRequestCallback(HttpEntity<byte[]> requestEntity) {
        return request -> {
            if (!requestEntity.getHeaders().isEmpty()) {
                requestEntity.getHeaders().forEach(
                    (key, values) -> request.getHeaders().put(key, new ArrayList<>(values))
                );
            }
            if (requestEntity.getBody() != null) {
                request.getBody().write(requestEntity.getBody());
            }
        };
    }
}
