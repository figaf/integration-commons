package com.figaf.integration.common.factory;

import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.tokenflows.TokenFlowException;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.impl.classic.HttpClients;


@Slf4j
class CloudConnectorAccessTokenProvider {

    private final XsuaaTokenFlows xsuaaTokenFlows;

    public CloudConnectorAccessTokenProvider(CloudConnectorParameters cloudConnectorParameters) {
        /*
        It's important here that XsuaaTokenFlows is created with client credentials from 'connectivity' service, not from 'xsuaa' service.
        Otherwise, proxy authorization won't work.
        At the moment library that creates a XsuaaTokenFlows bean can't handle it in that way, it can only initialize it fully from 'xsuaa' service.
         */
        xsuaaTokenFlows = new XsuaaTokenFlows(
            new CustomOAuth2TokenService(HttpClients.createDefault()),
            new XsuaaDefaultEndpoints(cloudConnectorParameters.getXsuaaUrl(), null),
            new ClientCredentials(cloudConnectorParameters.getClientId(), cloudConnectorParameters.getClientSecret())
        );
    }

    public OAuth2TokenResponse getToken() throws TokenFlowException {
        OAuth2TokenResponse oAuth2TokenResponse = xsuaaTokenFlows.clientCredentialsTokenFlow().execute();
        log.info("token was successfully received");
        return oAuth2TokenResponse;
    }
}

