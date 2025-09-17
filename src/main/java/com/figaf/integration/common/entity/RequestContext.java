package com.figaf.integration.common.entity;

import com.figaf.integration.common.exception.ClientIntegrationException;
import lombok.*;

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
    private String edgeCloudConnectorLocationId;
    private String publicApiUrl;
    private String host;
    private Integer port;
    private String protocol;
    private String username;
    private String password;
    private String iflowClientId;
    private String iflowClientSecret;
    private boolean isIntegrationSuite;
    private boolean preserveIntegrationSuiteUrl;

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

    public RequestContext withPreservingIntegrationSuiteUrl() {
        return this.toBuilder()
            .preserveIntegrationSuiteUrl(this.isIntegrationSuite)
            .build();
    }

    public ConnectionProperties getConnectionPropertiesForTesting() {
        if (Platform.CPI.equals(this.getPlatform()) && CLOUD_FOUNDRY.equals(this.getCloudPlatformType())) {
            return new ConnectionProperties(
                this.getIflowClientId(),
                this.getIflowClientSecret(),
                this.getHost(),
                Integer.toString(this.getPort()),
                this.getProtocol()
            );
        } else {
            return new ConnectionProperties(
                this.getUsername(),
                this.getPassword(),
                this.getHost(),
                Integer.toString(this.getPort()),
                this.getProtocol()
            );
        }
    }

    public ConnectionProperties getConnectionProperties() {
        if (this.isPreserveIntegrationSuiteUrl()) {
            return new ConnectionProperties(
                this.getUsername(),
                this.getPassword(),
                this.getHost(),
                Integer.toString(this.getPort()),
                this.getProtocol()
            );
        }
        String publicApiUrl = this.getPublicApiUrl();
        try {
            if (publicApiUrl == null || publicApiUrl.isBlank()) {
                throw new IllegalArgumentException("publicApiUrl is blank");
            }
            URI parsedPublicUrl = new URI(publicApiUrl);
            String scheme = parsedPublicUrl.getScheme();
            String host = parsedPublicUrl.getHost();
            if (scheme == null || host == null) {
                throw new IllegalArgumentException("publicApiUrl must include scheme and host");
            }
            int effectivePort = parsedPublicUrl.getPort() != -1
                ? parsedPublicUrl.getPort()
                : ("https".equalsIgnoreCase(scheme) ? 443 : 80);

            return new ConnectionProperties(
                this.getUsername(),
                this.getPassword(),
                host,
                Integer.toString(effectivePort),
                scheme.toLowerCase()
            );
        } catch (URISyntaxException | IllegalArgumentException ex) {
            throw new ClientIntegrationException(ex);
        }
    }

    public static ConnectionProperties createConnectionPropertiesForIFlow(RequestContext requestContext) {
        return new ConnectionProperties(
            requestContext.getIflowClientId(),
            requestContext.getIflowClientSecret(),
            requestContext.getHost(),
            requestContext.getPort() != null ? requestContext.getPort().toString() : null,
            requestContext.getProtocol()
        );
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

}
