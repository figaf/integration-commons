package com.figaf.integration.common.client.support;

import com.figaf.integration.common.client.support.parser.OAuthTokenParser;
import com.figaf.integration.common.entity.OAuthTokenRequestContext;
import com.figaf.integration.common.exception.ClientIntegrationException;
import com.figaf.integration.common.factory.HttpClientsFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.entity.UrlEncodedFormEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.message.BasicNameValuePair;
import org.springframework.http.*;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.Objects;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;

/**
 * @author Klochkov Sergey
 */
@Slf4j
@RequiredArgsConstructor
public class OAuthTokenInterceptor implements ClientHttpRequestInterceptor {

    private final OAuthTokenRequestContext oauthTokenRequestContext;
    private final OAuthTokenParser oauthTokenParser;
    private final HttpClientsFactory httpClientsFactory;
    private OAuthAccessToken accessToken;

    //very specific logic to mitigate the unresponsive IS behavior; once the root integration issue is isolated
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
            request.getHeaders().setBearerAuth(accessToken.getValue());
        }
        ClientHttpResponse response = null;
        for (int attempt = 1; attempt <= 5; attempt++) {
            response = execution.execute(request, body);
            if (response.getStatusCode() != HttpStatus.UNAUTHORIZED) {
                return response;
            }
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while backing off before token refresh", e);
            }
            response.close();
            synchronized (this) {
                accessToken = getToken();
                request.getHeaders().setBearerAuth(accessToken.getValue());
            }
        }
        return response;
    }

    private OAuthAccessToken getToken() {
        ResponseEntity<String> responseEntity;
        try {
            RestTemplate restTemplate = httpClientsFactory.createRestTemplate(true);
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
            responseEntity = restTemplate.exchange(uriBuilder.toUriString(), HttpMethod.POST, requestEntity, String.class);
        } catch (Exception ex) {
            throw new ClientIntegrationException("Can't get access token " + ex.getMessage(), ex);
        }
        if (!responseEntity.getStatusCode().is2xxSuccessful()) {
            throw new ClientIntegrationException("Can't get access token " + responseEntity.getBody());
        }
        return oauthTokenParser.parse(responseEntity.getBody());
    }

}
