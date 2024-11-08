package com.figaf.integration.common.entity;

import lombok.*;

/**
 * @author Arsenii Istlentev
 */
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@ToString(exclude = {"idpApiClientSecret", "clientSecret", "samlResponseSigner"})
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
    private String runtimeLocationId;

    private byte[] certificate;
    private String certificatePassword;

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

    public boolean isUseCustomIdp() {
        return webApiAccessMode == WebApiAccessMode.CUSTOM_IDP;
    }

    public boolean isUseSapPassport() {
        return webApiAccessMode == WebApiAccessMode.SAP_PASSPORT;
    }

}
