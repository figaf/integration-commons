package com.figaf.integration.common.factory;

import com.sap.cloud.security.servlet.MDCHelper;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.client.AbstractOAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.tokenflows.TokenCacheConfiguration;
import com.sap.cloud.security.xsuaa.util.HttpClientUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.entity.UrlEncodedFormEntity;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.message.BasicNameValuePair;
import org.json.JSONObject;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.*;
import static org.apache.hc.core5.http.HttpHeaders.USER_AGENT;

// Created from com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenService to support http client 5
@Slf4j
public class CustomOAuth2TokenService extends AbstractOAuth2TokenService {

    private final CloseableHttpClient httpClient;

    public CustomOAuth2TokenService(CloseableHttpClient httpClient) {
        this(httpClient, TokenCacheConfiguration.defaultConfiguration());
    }

    public CustomOAuth2TokenService(
        CloseableHttpClient httpClient,
        TokenCacheConfiguration tokenCacheConfiguration) {
        super(tokenCacheConfiguration);
        Assertions.assertNotNull(httpClient, "http client is required");
        this.httpClient = httpClient;
    }

    @Override
    protected OAuth2TokenResponse requestAccessToken(
        URI tokenEndpointUri, HttpHeaders headers,
        Map<String, String> parameters
    ) throws OAuth2ServiceException {
        HttpHeaders requestHeaders = new HttpHeaders();
        headers.getHeaders().forEach(h -> requestHeaders.withHeader(h.getName(), h.getValue()));
        requestHeaders.withHeader(MDCHelper.CORRELATION_HEADER, MDCHelper.getOrCreateCorrelationId());

        HttpPost httpPost = createHttpPost(tokenEndpointUri, requestHeaders, parameters);
        log.debug("access token request {} - {}", headers, parameters.entrySet().stream()
            .map(e -> {
                if (e.getKey().contains(PASSWORD) || e.getKey().contains(CLIENT_SECRET)
                    || e.getKey().contains(ASSERTION)) {
                    return new AbstractMap.SimpleImmutableEntry<>(e.getKey(), "****");
                }
                return e;
            })
            .toList());
        try {
            return executeRequest(httpPost);
        } catch (IOException | URISyntaxException e) {
            if (e instanceof OAuth2ServiceException oAuth2Exception)
                throw oAuth2Exception;
            throw new OAuth2ServiceException("Unexpected error retrieving JWT token: " + e);
        }
    }

    private OAuth2TokenResponse executeRequest(HttpPost httpPost) throws IOException, URISyntaxException {
        httpPost.addHeader(USER_AGENT, HttpClientUtil.getUserAgent());

        URI requestUri = httpPost.getUri();
        log.debug("Requesting access token from url {} with headers {}", requestUri,
            httpPost.getHeaders());

        String responseBody = httpClient.execute(httpPost, response -> {
            int statusCode = response.getCode();
            log.debug("Received statusCode {}", statusCode);
            String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            if (statusCode != HttpStatus.SC_OK) {
                log.debug("Received response body: {}", body);
                throw OAuth2ServiceException.builder("Error retrieving JWT token")
                    .withStatusCode(statusCode)
                    .withUri(requestUri)
                    .withHeaders(response.getHeaders() != null
                        ? Arrays.stream(response.getHeaders()).map(Header::toString).toArray(String[]::new)
                        : null
                    )
                    .withResponseBody(body)
                    .build();
            }

            return body;
        });

        return convertToOAuth2TokenResponse(responseBody);
    }

    private OAuth2TokenResponse convertToOAuth2TokenResponse(String responseBody)
        throws OAuth2ServiceException {
        Map<String, Object> accessTokenMap = new JSONObject(responseBody).toMap();
        String accessToken = getParameter(accessTokenMap, ACCESS_TOKEN);
        String refreshToken = getParameter(accessTokenMap, REFRESH_TOKEN);
        String expiresIn = getParameter(accessTokenMap, EXPIRES_IN);
        String tokenType = getParameter(accessTokenMap, TOKEN_TYPE);
        return new OAuth2TokenResponse(accessToken, convertExpiresInToLong(expiresIn),
            refreshToken, tokenType);
    }

    private Long convertExpiresInToLong(String expiresIn) throws OAuth2ServiceException {
        try {
            return Long.parseLong(expiresIn);
        } catch (NumberFormatException e) {
            throw new OAuth2ServiceException(
                String.format("Cannot convert expires_in from response (%s) to long", expiresIn));
        }
    }

    private String getParameter(Map<String, Object> accessTokenMap, String key) {
        return String.valueOf(accessTokenMap.get(key));
    }

    private HttpPost createHttpPost(URI uri, HttpHeaders headers, Map<String, String> parameters)
        throws OAuth2ServiceException {
        HttpPost httpPost = new HttpPost(uri);
        headers.getHeaders().forEach(header -> httpPost.setHeader(header.getName(), header.getValue()));
        List<BasicNameValuePair> basicNameValuePairs = parameters.entrySet().stream()
            .map(entry -> new BasicNameValuePair(entry.getKey(), entry.getValue()))
            .toList();
        try {
            httpPost.setEntity(new UrlEncodedFormEntity(basicNameValuePairs));
        } catch (Exception e) {
            throw new OAuth2ServiceException("Unexpected error parsing URI: " + e.getMessage());
        }
        return httpPost;
    }

}
