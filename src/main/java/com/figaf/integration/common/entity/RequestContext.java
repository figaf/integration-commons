package com.figaf.integration.common.entity;

import com.figaf.integration.common.exception.ClientIntegrationException;
import lombok.*;
import org.apache.commons.lang3.exception.ExceptionUtils;

import java.net.URI;
import java.net.URISyntaxException;

import static com.figaf.integration.common.entity.CloudPlatformType.CLOUD_FOUNDRY;

/**
 * @author Arsenii Istlentev
 */
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@ToString(of = {"connectionProperties", "cloudPlatformType", "platform", "restTemplateWrapperKey", "loginPageUrl", "ssoUrl", "webApiAccessMode", "samlUrl", "figafAgentId",
    "idpName", "idpApiClientId", "oauthUrl", "clientId", "authenticationType", "defaultRuntimeLocationId", "runtimeLocationId"
})
@Builder(toBuilder = true)
public class RequestContext {

    private ConnectionProperties connectionProperties;
    private CloudPlatformType cloudPlatformType;
    private Platform platform;
    private String restTemplateWrapperKey;
    private String loginPageUrl;
    private String ssoUrl;
    private WebApiAccessMode webApiAccessMode;
    private String samlUrl;
    private String figafAgentId;
    private String idpName;
    private String idpApiClientId;
    private String idpApiClientSecret;
    private SamlResponseSigner samlResponseSigner;
    private String oauthUrl;
    private String clientId;
    private String clientSecret;
    private AuthenticationType authenticationType;
    private String defaultRuntimeLocationId;
    private String runtimeLocationId;
    private byte[] certificate;
    private String certificatePassword;
    private boolean onPremiseEdgeSystem;
    private boolean isEdge;
    private String edgeCloudConnectorLocationId;
    private String userName;
    private String password;
    private String connectionPropertiesClientId;
    private String connectionPropertiesClientSecret;
    private String host;
    private int port;
    private String protocol;
    private String publicApiUrl;

    public RequestContext(
        ConnectionProperties connectionProperties,
        CloudPlatformType cloudPlatformType,
        Platform platform,
        String restTemplateWrapperKey
    ) {
        this.connectionProperties = connectionProperties;
        this.cloudPlatformType = cloudPlatformType;
        this.platform = platform;
        this.restTemplateWrapperKey = restTemplateWrapperKey;
    }

    public static RequestContext pro(ConnectionProperties connectionProperties) {
        return new RequestContext(
            connectionProperties,
            null,
            Platform.PRO,
            null
        );
    }

    public static RequestContext cpiNeo(ConnectionProperties connectionProperties) {
        return new RequestContext(
            connectionProperties,
            CloudPlatformType.NEO,
            Platform.CPI,
            null
        );
    }

    public static RequestContext cpiCloudFoundry(ConnectionProperties connectionProperties, String restTemplateWrapperKey) {
        return new RequestContext(
            connectionProperties,
            CLOUD_FOUNDRY,
            Platform.CPI,
            restTemplateWrapperKey
        );
    }

    public static RequestContext apiMgmtNeo(ConnectionProperties connectionProperties) {
        return new RequestContext(
            connectionProperties,
            CloudPlatformType.NEO,
            Platform.API_MANAGEMENT,
            null
        );
    }

    public static RequestContext apiMgmtCloudFoundry(ConnectionProperties connectionProperties, String restTemplateWrapperKey) {
        return new RequestContext(
            connectionProperties,
            CLOUD_FOUNDRY,
            Platform.API_MANAGEMENT,
            restTemplateWrapperKey
        );
    }

    public static RequestContext apiHub(ConnectionProperties connectionProperties) {
        return new RequestContext(
            connectionProperties,
            null,
            Platform.API_HUB,
            null
        );
    }

    public String getRestTemplateWrapperKey() {
        if (restTemplateWrapperKey == null) {
            restTemplateWrapperKey = "";
        }
        return restTemplateWrapperKey;
    }

    public boolean isUseCustomIdp() {
        return webApiAccessMode == WebApiAccessMode.CUSTOM_IDP;
    }

    public boolean isUseSapPassport() {
        return webApiAccessMode == WebApiAccessMode.SAP_PASSPORT;
    }

    public boolean isSapIdentityService() {
        return webApiAccessMode == WebApiAccessMode.SAP_IDENTITY_SERVICE;
    }

    public ConnectionProperties createConnectionPropertiesForTesting() {
        if (Platform.CPI.equals(getPlatform()) && CLOUD_FOUNDRY.equals(getCloudPlatformType())) {
            if (!isEdge()) {
                try {
                    URI uri = new URI(this.getPublicApiUrl());
                    int port = uri.getPort() != -1 ? uri.getPort() : defaultPort(uri.getScheme());
                    return connectionPropertiesFor(uri.getHost(), port, uri.getScheme());
                } catch (URISyntaxException e) {
                    throw new ClientIntegrationException(String.format("Can't parse url argument: %s", ExceptionUtils.getMessage(e)));
                }
            }
            return connectionPropertiesFor(getHost(), getPort(), getProtocol());
        }
        return createConnectionPropertiesWithUserNameAndPassword();
    }

    public ConnectionProperties createConnectionPropertiesForMplNonEdge() {
        if (Platform.CPI.equals(this.getPlatform()) && CloudPlatformType.CLOUD_FOUNDRY.equals(this.getCloudPlatformType())) {
            try {
                URI uri = new URI(this.getPublicApiUrl());
                int port = uri.getPort() != -1 ? uri.getPort() : this.defaultPort(uri.getScheme());
                return this.connectionPropertiesFor(uri.getHost(), port, uri.getScheme());
            } catch (URISyntaxException var3) {
                throw new ClientIntegrationException(String.format("Can't parse url argument: %s", ExceptionUtils.getMessage(var3)));
            }
        }
        return this.createConnectionPropertiesWithUserNameAndPassword();
    }

    public ConnectionProperties createConnectionPropertiesWithUserNameAndPassword() {
        return new ConnectionProperties(
            this.getUserName(),
            this.getPassword(),
            this.getHost(),
            Integer.toString(this.getPort()),
            this.getProtocol()
        );
    }

    private int defaultPort(String scheme) {
        return "https".equalsIgnoreCase(scheme) ? 443 : 80;
    }

    private ConnectionProperties connectionPropertiesFor(String host, int port, String scheme) {
        return new ConnectionProperties(
            getConnectionPropertiesClientId(),
            getConnectionPropertiesClientSecret(),
            host,
            Integer.toString(port),
            scheme
        );
    }
}
