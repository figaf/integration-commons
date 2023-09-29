package com.figaf.integration.common.entity;

import lombok.*;

/**
 * @author Arsenii Istlentev
 */
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@ToString(exclude = {"idpApiClientSecret", "clientSecret"})
public class RequestContext {

    private ConnectionProperties connectionProperties;
    private CloudPlatformType cloudPlatformType;
    private Platform platform;
    private String restTemplateWrapperKey;

    private String loginPageUrl;
    private String integrationSuiteUrl;
    private String ssoUrl;
    private boolean isIntegrationSuite;
    private boolean useCustomIdp;
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

    public RequestContext(ConnectionProperties connectionProperties, CloudPlatformType cloudPlatformType, Platform platform, String restTemplateWrapperKey) {
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
                CloudPlatformType.CLOUD_FOUNDRY,
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
                CloudPlatformType.CLOUD_FOUNDRY,
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
}
