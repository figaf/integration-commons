package com.figaf.integration.common.entity;

import com.figaf.integration.common.exception.ClientIntegrationException;
import lombok.*;
import org.apache.commons.lang3.exception.ExceptionUtils;

import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.figaf.integration.common.entity.CloudPlatformType.CLOUD_FOUNDRY;

/**
 * @author Ilya Nesterov
 */
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@ToString(of = {"username", "host", "port", "protocol"})
public class ConnectionProperties implements Serializable {

    private String username;
    private String password;
    private String host;
    private String port;
    private String protocol;

    public ConnectionProperties(String url, String username, String password) {
        Pattern pattern = Pattern.compile("(https?):\\/\\/([^:]+):*(\\d*)");
        Matcher matcher = pattern.matcher(url);
        if (matcher.find()) {
            this.protocol = matcher.group(1);
            this.host = matcher.group(2);
            this.port = matcher.group(3);
        }
        this.username = username;
        this.password = password;
    }

    public String getURL() {
        StringBuilder urlBuilder = new StringBuilder();

        if (protocol.toUpperCase().equals("HTTPS")) {
            urlBuilder.append("https://");
        } else {
            urlBuilder.append("http://");
        }
        urlBuilder.append(host);
        urlBuilder.append(":");
        urlBuilder.append(port);
        return urlBuilder.toString();
    }


    public static String buildUrl(String protocol, String host, String port) {
        return String.format("%s://%s%s", protocol, host, port != null ? ":" + port : "");
    }

    public static ConnectionProperties createConnectionPropertiesForIFlow(
        ConnectionData connectionData,
        Platform platform,
        CloudPlatformType cloudPlatformType,
        boolean isEdge
    ) {
        if (Platform.CPI.equals(platform) && CLOUD_FOUNDRY.equals(cloudPlatformType)) {
            if (!isEdge) {
                return creConnectionPropertiesWithPublicApiUrl(connectionData);
            }
            return connectionPropertiesFor(connectionData);
        }
        return createConnectionPropertiesWithUserNameAndPassword(connectionData);
    }

    private static ConnectionProperties creConnectionPropertiesWithPublicApiUrl(ConnectionData connectionData) {
        try {
            URI uri = new URI(connectionData.getPublicApiUrl());
            int uriPort = uri.getPort() != -1 ? uri.getPort() : defaultPort(uri.getScheme());
            return connectionPropertiesFor(uri.getHost(), uriPort, uri.getScheme(), connectionData);
        } catch (URISyntaxException ex) {
            throw new ClientIntegrationException(String.format("Can't parse url argument: %s", ExceptionUtils.getMessage(ex)));
        }
    }


    public static ConnectionProperties createConnectionPropertiesForPublicApi(
        ConnectionData connectionData,
        Platform platform,
        CloudPlatformType cloudPlatformType
    ) {
        if (Platform.CPI.equals(platform) && CloudPlatformType.CLOUD_FOUNDRY.equals(cloudPlatformType)) {
            return creConnectionPropertiesWithPublicApiUrl(connectionData);
        }
        return createConnectionPropertiesWithUserNameAndPassword(connectionData);
    }

    public static ConnectionProperties createConnectionPropertiesWithUserNameAndPassword(ConnectionData connectionData) {
        return new ConnectionProperties(
            connectionData.getUsername(),
            connectionData.getPassword(),
            connectionData.getHost(),
            Integer.toString(connectionData.getPort()),
            connectionData.getProtocol()
        );
    }

    private static int defaultPort(String scheme) {
        return "https".equalsIgnoreCase(scheme) ? 443 : 80;
    }

    private static ConnectionProperties connectionPropertiesFor(ConnectionData connectionData) {
        return new ConnectionProperties(
            connectionData.getIflowClientId(),
            connectionData.getIflowClientSecret(),
            connectionData.getHost(),
            Integer.toString(connectionData.getPort()),
            connectionData.getProtocol()
        );
    }

    private static ConnectionProperties connectionPropertiesFor(String host, int port, String protocol, ConnectionData connectionData) {
        return new ConnectionProperties(
            connectionData.getIflowClientId(),
            connectionData.getIflowClientSecret(),
            host,
            Integer.toString(port),
            protocol
        );
    }

    public String getUrlRemovingDefaultPortIfNecessary() {
        if ("http".equals(protocol) && Objects.equals(port, "80") || "https".equals(protocol) && Objects.equals(port, "443")) {
            return buildUrl(protocol, host, null);
        } else {
            return buildUrl(protocol, host, port);
        }
    }


}
