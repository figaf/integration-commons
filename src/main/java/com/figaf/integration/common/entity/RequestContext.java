package com.figaf.integration.common.entity;

import com.figaf.integration.common.exception.ClientIntegrationException;
import lombok.*;
import org.apache.commons.lang3.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;

import static com.figaf.integration.common.entity.CloudPlatformType.CLOUD_FOUNDRY;
import static java.lang.String.format;

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

    private static final String INTEGRATION_SUITE_URL_KEY_POSTFIX = "_INTEGRATION_SUITE_URL_KEY_POSTFIX";

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

    /*
           It's required to update restTemplateWrapperKey because requests to the main web api host and IS host don't have compatible session.
           In other words, when they are executed 1 by 1, for the second request it requires to process authentication flow fully
           e2e to get it successfully processed.
           But it won't work in that way because of the fix for "waiting" authentication attempts that skips authentication
           for all threads except the first. See comments in BaseClient.makeAuthRequestsWithLock.
           It's more efficient to keep a different session context for requests to IS host
    */
    public RequestContext withPreservingIntegrationSuiteUrl() {
        //temporary for now we expect that restTemplateWrapperKey will be initialized with agentId from user(irt from example)
        String computedRestTemplateKey = this.isIntegrationSuite && !getRestTemplateWrapperKey().contains(INTEGRATION_SUITE_URL_KEY_POSTFIX)
            ? buildKeyForWebApiRequestsWithIntegrationSuiteUrl(getRestTemplateWrapperKey(), this.runtimeLocationId)
            : getRestTemplateWrapperKey();

        return toBuilder()
            .preserveIntegrationSuiteUrl(this.isIntegrationSuite)
            .restTemplateWrapperKey(computedRestTemplateKey)
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
        String scheme = this.getProtocol();
        String host = this.getHost();
        int port = this.getPort();

        if (
            !this.isPreserveIntegrationSuiteUrl()
             && StringUtils.isNotBlank(this.getPublicApiUrl())
             && (this.platform == Platform.CPI || this.platform == Platform.API_MANAGEMENT)
        ) {
            try {
                URI parsedPublicUrl = new URI(this.getPublicApiUrl());
                String parsedScheme = parsedPublicUrl.getScheme();
                String parsedHost = parsedPublicUrl.getHost();
                if (parsedScheme == null || parsedHost == null) {
                    throw new IllegalArgumentException("publicApiUrl must include scheme and host");
                }
                scheme = parsedScheme.toLowerCase();
                host = parsedHost;
                port = parsedPublicUrl.getPort() != -1 ? parsedPublicUrl.getPort() : ("https".equalsIgnoreCase(scheme) ? 443 : 80);
            } catch (URISyntaxException | IllegalArgumentException ex) {
                throw new ClientIntegrationException(ex);
            }
        }

        return new ConnectionProperties(
            this.getUsername(),
            this.getPassword(),
            host,
            String.valueOf(port),
            scheme
        );
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

    private String buildKeyForWebApiRequestsWithIntegrationSuiteUrl(String agentId, String runtimeLocationId) {
        if (StringUtils.isNotBlank(runtimeLocationId)) {
            return format("%s_%s%s", agentId, runtimeLocationId, INTEGRATION_SUITE_URL_KEY_POSTFIX);
        }
        return agentId + INTEGRATION_SUITE_URL_KEY_POSTFIX;
    }
}
