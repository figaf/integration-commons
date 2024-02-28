package com.figaf.integration.common.factory;

import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.tokenflows.TokenFlowException;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.impl.client.HttpClients;


@Slf4j
public class CloudConnectorAccessTokenProvider {

    public OAuth2TokenResponse getToken(CloudConnectorParameters cloudConnectorParameters) throws TokenFlowException {
        XsuaaTokenFlows tokenFlows = new XsuaaTokenFlows(
            new DefaultOAuth2TokenService(HttpClients.createDefault()),
            new XsuaaDefaultEndpoints(cloudConnectorParameters.getXsuaaUrl(), null),
            new ClientCredentials(cloudConnectorParameters.getClientId(), cloudConnectorParameters.getClientSecret())
        );
        OAuth2TokenResponse oAuth2TokenResponse = tokenFlows.clientCredentialsTokenFlow().execute();
        log.info("token was successfully received");
        return oAuth2TokenResponse;
    }
}

