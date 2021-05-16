package com.figaf.integration.common.client.support;

import com.figaf.integration.common.client.support.parser.OAuthTokenParser;
import com.figaf.integration.common.entity.OAuthTokenRequestContext;
import com.figaf.integration.common.exception.ClientIntegrationException;
import com.figaf.integration.common.factory.HttpClientsFactory;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.springframework.http.*;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

/**
 * @author Klochkov Sergey
 */
@Slf4j
public class OAuthTokenInterceptor<T extends OAuthTokenParser> implements ClientHttpRequestInterceptor {

    private final OAuthTokenRequestContext oauthTokenRequestContext;
    private final T oauthTokenParser;
    private final HttpClientsFactory httpClientsFactory;
    private OAuthAccessToken accessToken;

    public OAuthTokenInterceptor(
        OAuthTokenRequestContext oAuthTokenRequestContext,
        T oauthTokenParser,
        HttpClientsFactory httpClientsFactory
    ) {
        this.oauthTokenRequestContext = oAuthTokenRequestContext;
        this.oauthTokenParser = oauthTokenParser;
        this.httpClientsFactory = httpClientsFactory;
    }

    @Override
    public ClientHttpResponse intercept(
        HttpRequest request,
        byte[] body,
        ClientHttpRequestExecution execution
    ) throws IOException {
        synchronized (this) {
            if (accessToken == null || accessToken.isExpired()) {
                accessToken = getToken();
            }
            request.getHeaders().add("Authorization", "Bearer " + accessToken.getValue());
        }
        return execution.execute(request, body);
    }

    private OAuthAccessToken getToken() throws IOException {
        RestTemplate restTemplate = httpClientsFactory.createRestTemplate();
        String oauthRequestBody = EntityUtils.toString(new UrlEncodedFormEntity(asList(
            new BasicNameValuePair("grant_type", "client_credentials"),
            new BasicNameValuePair("scope", ""),
            new BasicNameValuePair("client_id", oauthTokenRequestContext.getClientId()),
            new BasicNameValuePair("client_secret", oauthTokenRequestContext.getClientSecret())
        )));
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.set("Content-Type", MediaType.APPLICATION_FORM_URLENCODED_VALUE);

        UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromHttpUrl(oauthTokenRequestContext.getOauthTokenUrl());
        HttpEntity<byte[]> requestEntity = new HttpEntity<>(oauthRequestBody.getBytes(UTF_8), httpHeaders);
        ResponseEntity<String> responseEntity = restTemplate.exchange(uriBuilder.toUriString(), HttpMethod.POST, requestEntity, String.class);

        if (responseEntity.getStatusCode() == UNAUTHORIZED && StringUtils.contains(responseEntity.getBody(), "invalid_token")) {
            throw new ClientIntegrationException("Login/password are not correct");
        }
        return oauthTokenParser.parse(responseEntity.getBody());
    }

}
