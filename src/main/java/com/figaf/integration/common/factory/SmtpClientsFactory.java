package com.figaf.integration.common.factory;

import lombok.Getter;

import java.util.Optional;

@Getter
public class SmtpClientsFactory {

    private final CloudConnectorParameters cloudConnectorParameters;

    private final CloudConnectorAccessTokenProvider accessTokenProvider;

    public static SmtpClientsFactory getForOnPremiseIntegration() {
        return new SmtpClientsFactory(CloudConnectorParameters.getInstance(), new CloudConnectorAccessTokenProvider());
    }

    private SmtpClientsFactory(CloudConnectorParameters cloudConnectorParameters, CloudConnectorAccessTokenProvider accessTokenProvider) {
        this.accessTokenProvider = accessTokenProvider;
        validateCloudConnectorParameters(cloudConnectorParameters);
        this.cloudConnectorParameters = cloudConnectorParameters;
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
