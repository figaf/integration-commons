package com.figaf.integration.common.factory;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.protocol.HttpContext;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.client.ClientCredentialsOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import java.time.Instant;

/**
 * @author Arsenii Istlentev
 */
@Slf4j
class OAuthHttpRequestInterceptor implements HttpRequestInterceptor {

    private final CloudConnectorParameters cloudConnectorParameters;
    private final String locationId;

    private OAuth2AccessToken accessToken;

    public OAuthHttpRequestInterceptor(CloudConnectorParameters cloudConnectorParameters, String locationId) {
        this.cloudConnectorParameters = cloudConnectorParameters;
        this.locationId = locationId;
    }

    @Override
    public void process(HttpRequest request, HttpContext context) {
        if (cloudConnectorParameters == null) {
            return;
        }

        synchronized (this) {
            if (accessToken == null || (accessToken.getExpiresAt() != null && accessToken.getExpiresAt().isBefore(Instant.now()))) {
                accessToken = getToken(cloudConnectorParameters);
            }
            request.addHeader("Proxy-Authorization", String.format("%s %s", accessToken.getTokenType().getValue(), accessToken.getTokenValue()));
            if (StringUtils.isNotEmpty(locationId)) {
                request.addHeader("SAP-Connectivity-SCC-Location_ID", locationId);
            }
        }
    }

    //taken mostly from https://help.sap.com/viewer/cca91383641e40ffbe03bdc78f00f681/Cloud/en-US/313b215066a8400db461b311e01bd99b.html
    private OAuth2AccessToken getToken(CloudConnectorParameters cloudConnectorParameters) {

        // make request to UAA to retrieve access token
        ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("some-id").
                authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).
                clientId(cloudConnectorParameters.getClientId()).
                clientSecret(cloudConnectorParameters.getClientSecret()).
                authorizationUri(cloudConnectorParameters.getXsuaaUrl() + "/oauth/authorize").
                tokenUri(cloudConnectorParameters.getXsuaaUrl() + "/oauth/token").
                build();

        OAuth2AuthorizationContext xsuaaContext = OAuth2AuthorizationContext.withClientRegistration(clientRegistration).
                principal(new AbstractAuthenticationToken(null) {
                    @Override
                    public Object getPrincipal() {
                        return null;
                    }

                    @Override
                    public Object getCredentials() {
                        return null;
                    }

                    @Override
                    public String getName() {
                        return "dummyPrincipalName";// There is no principal in the client credentials authorization grant but a non-empty name is still required.
                    }
                }).build();

        OAuth2AuthorizedClientProvider clientCredentialsAccessTokenProvider = new ClientCredentialsOAuth2AuthorizedClientProvider();
        OAuth2AccessToken token = clientCredentialsAccessTokenProvider.authorize(xsuaaContext).getAccessToken();

        log.info("token was successfully received");

        return token;
    }

}
