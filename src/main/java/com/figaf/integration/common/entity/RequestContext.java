package com.figaf.integration.common.entity;

import com.figaf.integration.common.entity.message_sender.MessageSendingAdditionalProperties;
import com.figaf.integration.common.exception.ClientIntegrationException;
import lombok.*;

import java.net.URI;
import java.net.URISyntaxException;

import static com.figaf.integration.common.entity.CloudPlatformType.CLOUD_FOUNDRY;
import static com.figaf.integration.common.entity.Platform.API_MANAGEMENT;
import static java.lang.String.format;

/**
 * @author Arsenii Istlentev
 */
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@ToString(of = {"cloudPlatformType", "platform", "restTemplateWrapperKey", "loginPageUrl", "ssoUrl", "webApiAccessMode", "samlUrl", "figafAgentId",
    "idpName", "idpApiClientId", "oauthUrl", "clientId", "authenticationType", "defaultRuntimeLocationId", "runtimeLocationId"
})
@Builder(toBuilder = true)
public class RequestContext {

    private static final String INTEGRATION_SUITE_URL_KEY_POSTFIX = "_INTEGRATION_SUITE_URL_KEY_POSTFIX";
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
    private boolean integrationSuite;
    private boolean preserveIntegrationSuiteUrl;
    private MessageSendingAdditionalProperties messageSendingAdditionalProperties;
    //oauth2 api management
    private boolean useOAuthForTesting;
    private String apiProxyClientId;
    private String credentialValue;

    public RequestContext(
        CloudPlatformType cloudPlatformType,
        Platform platform,
        String restTemplateWrapperKey
    ) {
        this.cloudPlatformType = cloudPlatformType;
        this.platform = platform;
        this.restTemplateWrapperKey = restTemplateWrapperKey;
    }

    public static String buildKeyForWebApiRequestsWithIntegrationSuiteUrl(String originalKey, String runtimeLocationId) {
        if (runtimeLocationId != null && !runtimeLocationId.trim().isEmpty()) {
            return format("%s_%s%s", originalKey, runtimeLocationId, INTEGRATION_SUITE_URL_KEY_POSTFIX);
        }
        return originalKey + INTEGRATION_SUITE_URL_KEY_POSTFIX;
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
        String computedRestTemplateKey = isIntegrationSuite() && !getRestTemplateWrapperKey().contains(INTEGRATION_SUITE_URL_KEY_POSTFIX)
            ? buildKeyForWebApiRequestsWithIntegrationSuiteUrl(getRestTemplateWrapperKey(), getRuntimeLocationId())
            : getRestTemplateWrapperKey();

        return toBuilder()
            .preserveIntegrationSuiteUrl(isIntegrationSuite())
            .restTemplateWrapperKey(computedRestTemplateKey)
            .build();
    }

    public ConnectionProperties getConnectionPropertiesForTesting() {
        String host = getHost();
        String port = Integer.toString(getPort());
        String protocol = getProtocol();

        Platform platform = getPlatform();
        if (platform == Platform.API_MANAGEMENT) {
            boolean useOAuth = isUseOAuthForTesting();
            boolean isOauth = getAuthenticationType() == AuthenticationType.OAUTH;
            String effectiveHost = host;
            String effectivePort = port;
            String effectiveProtocol = protocol;

            if (isOauth) {
                ParsedUrl parsedPublicUrl = parsePublicUrl(getPublicApiUrl());
                effectiveHost = parsedPublicUrl.host();
                effectivePort = String.valueOf(parsedPublicUrl.port());
                effectiveProtocol = parsedPublicUrl.scheme();
            }

            String usernameOrClientId = useOAuth ? getApiProxyClientId() : getUsername();
            String passwordOrCredential = useOAuth ? getCredentialValue() : getPassword();

            return new ConnectionProperties(
                usernameOrClientId,
                passwordOrCredential,
                effectiveHost,
                effectivePort,
                effectiveProtocol
            );
        }

        if (platform == Platform.CPI && getCloudPlatformType() == CloudPlatformType.CLOUD_FOUNDRY) {
            return new ConnectionProperties(getIflowClientId(), getIflowClientSecret(), host, port, protocol);
        }

        return new ConnectionProperties(getUsername(), getPassword(), host, port, protocol);
    }

    public ConnectionProperties getConnectionProperties() {
        String scheme = getProtocol();
        String host = getHost();
        int port = getPort();
        if (getPlatform() == API_MANAGEMENT && getAuthenticationType() == AuthenticationType.OAUTH
            && getPublicApiUrl() != null
            && !getPublicApiUrl().isBlank()
        ) {
            ParsedUrl parsedPublicUrl = parsePublicUrl(getPublicApiUrl());
            return new ConnectionProperties(
                getUsername(),
                getPassword(),
                parsedPublicUrl.host(),
                String.valueOf(parsedPublicUrl.port()),
                parsedPublicUrl.scheme()
            );
        }
        if (!isPreserveIntegrationSuiteUrl()
            && getPublicApiUrl() != null && !getPublicApiUrl().isBlank()
            && getPlatform() == Platform.CPI
        ) {
            ParsedUrl parsedUrl = parsePublicUrl(getPublicApiUrl());
            scheme = parsedUrl.scheme();
            host = parsedUrl.host();
            port = parsedUrl.port();
        }

        return new ConnectionProperties(
            getUsername(),
            getPassword(),
            host,
            String.valueOf(port),
            scheme
        );
    }

    public static RequestContext pro() {
        return new RequestContext(
            null,
            Platform.PRO,
            null
        );
    }

    public static RequestContext cpiNeo() {
        return new RequestContext(
            CloudPlatformType.NEO,
            Platform.CPI,
            null
        );
    }

    public static RequestContext cpiCloudFoundry(String restTemplateWrapperKey) {
        return new RequestContext(
            CLOUD_FOUNDRY,
            Platform.CPI,
            restTemplateWrapperKey
        );
    }

    public static RequestContext apiMgmtNeo() {
        return new RequestContext(
            CloudPlatformType.NEO,
            API_MANAGEMENT,
            null
        );
    }

    public static RequestContext apiMgmtCloudFoundry(String restTemplateWrapperKey) {
        return new RequestContext(
            CLOUD_FOUNDRY,
            API_MANAGEMENT,
            restTemplateWrapperKey
        );
    }

    public static RequestContext apiHub() {
        return new RequestContext(
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

    private ParsedUrl parsePublicUrl(String publicApiUrl) {
        try {
            URI parsedUrl = new URI(publicApiUrl);
            String scheme = parsedUrl.getScheme();
            String host = parsedUrl.getHost();

            if (scheme == null || host == null) {
                throw new IllegalArgumentException("publicApiUrl must include scheme and host");
            }

            int port = parsedUrl.getPort() != -1
                ? parsedUrl.getPort()
                : ("https".equalsIgnoreCase(scheme) ? 443 : 80);

            return new ParsedUrl(scheme, host, port);
        } catch (URISyntaxException | IllegalArgumentException ex) {
            throw new ClientIntegrationException("Failed to parse publicApiUrl: " + publicApiUrl, ex);
        }
    }

    private record ParsedUrl(String scheme, String host, int port) {
    }
}
