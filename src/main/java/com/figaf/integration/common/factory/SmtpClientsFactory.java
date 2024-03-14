package com.figaf.integration.common.factory;

import com.figaf.integration.common.socket.ConnectivitySocks5ProxySocket;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.tokenflows.TokenFlowException;
import lombok.Getter;

import java.util.Optional;

@Getter
public class SmtpClientsFactory {

    private final CloudConnectorParameters cloudConnectorParameters;

    private final CloudConnectorAccessTokenProvider accessTokenProvider;

    private final String locationId;


    public static SmtpClientsFactory getForOnPremiseIntegration(String locationId) {
        return new SmtpClientsFactory(
            CloudConnectorParameters.getInstance(),
            new CloudConnectorAccessTokenProvider(),
            locationId
        );
    }

    private SmtpClientsFactory(CloudConnectorParameters cloudConnectorParameters, CloudConnectorAccessTokenProvider accessTokenProvider, String locationId) {
        this.accessTokenProvider = accessTokenProvider;
        this.locationId = locationId;
        validateCloudConnectorParameters(cloudConnectorParameters);
        this.cloudConnectorParameters = cloudConnectorParameters;
    }

    public ConnectivitySocks5ProxySocket createAuthorizedSocks5ProxySocket() throws TokenFlowException {
        OAuth2TokenResponse oAuth2TokenResponse = this.accessTokenProvider.getToken(cloudConnectorParameters);
        return new ConnectivitySocks5ProxySocket(
            oAuth2TokenResponse.getAccessToken(),
            locationId,
            cloudConnectorParameters.getConnectionProxyHost(),
            cloudConnectorParameters.getConnectionProxyPortSocks5());
    }

    private void validateCloudConnectorParameters(CloudConnectorParameters cloudConnectorParameters) {
        if (!Optional.ofNullable(cloudConnectorParameters).isPresent()) {
            throw new IllegalArgumentException("cloudConnectorParameters are not defined");
        }
        if (!Optional.ofNullable(cloudConnectorParameters.getConnectionProxyPortSocks5()).isPresent()) {
            throw new IllegalArgumentException("proxyPortSocks5 is not defined");
        }
        if (!Optional.ofNullable(cloudConnectorParameters.getConnectionProxyHost()).isPresent()) {
            throw new IllegalArgumentException("proxyHost is not defined");
        }
    }
}
