package com.figaf.integration.common.factory;

import com.figaf.integration.common.client.CloudConnectorEmailClient;
import lombok.Getter;

import java.util.Optional;

@Getter
public class SmtpClientsFactory {

    private final CloudConnectorEmailClient cloudConnectorEmailClient;

    public static SmtpClientsFactory getForOnPremiseIntegration(String host, String locationId, int port) {
        return new SmtpClientsFactory(CloudConnectorParameters.getInstance(), host, locationId, port);
    }

    private SmtpClientsFactory(
        CloudConnectorParameters cloudConnectorParameters,
        String host,
        String locationId,
        int port
    ) {
        validateCloudConnectorParameters(cloudConnectorParameters);
        this.cloudConnectorEmailClient = new CloudConnectorEmailClient(cloudConnectorParameters, host, locationId, port);
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
