package com.figaf.integration.common.client;

import com.figaf.integration.common.entity.ConnectionProperties;
import com.figaf.integration.common.entity.RequestContext;
import com.figaf.integration.common.entity.message_sender.MessageSendingAdditionalProperties;
import com.figaf.integration.common.factory.HttpClientsFactory;
import com.figaf.integration.common.factory.RestTemplateWrapperFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * @author Klochkov Sergey
 */
@Slf4j
public abstract class MessageSender {

    protected final HttpClientsFactory httpClientsFactory;
    protected final RestTemplateWrapperHolder restTemplateWrapperHolder;

    protected MessageSender(HttpClientsFactory httpClientsFactory) {
        this.httpClientsFactory = httpClientsFactory;
        this.restTemplateWrapperHolder = new RestTemplateWrapperHolder(new RestTemplateWrapperFactory(httpClientsFactory));
    }

    public ResponseEntity<String> sendMessage(
        RequestContext requestContext,
        String url,
        HttpMethod httpMethod,
        HttpEntity<byte[]> requestEntity
    ) {
        MessageSendingAdditionalProperties messageSendingAdditionalProperties = requestContext.getMessageSendingAdditionalProperties();
        ConnectionProperties connectionProperties = requestContext.getConnectionProperties();
        log.debug("#sendMessage(ConnectionProperties testSystemProperties, String url, HttpMethod httpMethod, " +
            "HttpEntity<byte[]> requestEntity, MessageSendingAdditionalProperties messageSendingAdditionalProperties): " +
            "{}, {}, {}, {}, {}", connectionProperties, url, httpMethod, requestEntity, messageSendingAdditionalProperties);
        return switch (messageSendingAdditionalProperties.getAuthenticationType()) {
            case BASIC -> sendMessageWithBasicAuthentication(
                requestContext,
                url,
                httpMethod,
                requestEntity,
                messageSendingAdditionalProperties
            );
            case OAUTH -> sendMessageWithOAuth(
                requestContext,
                url,
                httpMethod,
                requestEntity,
                messageSendingAdditionalProperties
            );
        };
    }

    public abstract ResponseEntity<String> sendMessageWithBasicAuthentication(
        RequestContext requestContext,
        String url,
        HttpMethod httpMethod,
        HttpEntity<byte[]> requestEntity,
        MessageSendingAdditionalProperties messageSendingAdditionalProperties
    );

    public abstract ResponseEntity<String> sendMessageWithOAuth(
        RequestContext requestContext,
        String url,
        HttpMethod httpMethod,
        HttpEntity<byte[]> requestEntity,
        MessageSendingAdditionalProperties messageSendingAdditionalProperties
    );

    public ResponseEntity<String> sendMessageWithoutAuthentication(
        RequestContext requestContext,
        String url,
        HttpMethod httpMethod,
        HttpEntity<byte[]> requestEntity
    ) {
        RestTemplate restTemplate = restTemplateWrapperHolder.getOrCreateRestTemplateWrapperSingleton(requestContext).getRestTemplate();
        UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromHttpUrl(url);
        String uri = uriBuilder.toUriString();
        return restTemplate.exchange(
            uri,
            httpMethod,
            requestEntity,
            String.class
        );
    }

}
