package com.figaf.integration.common.entity;

import com.figaf.integration.common.entity.message_sender.MessageSendingAdditionalProperties;
import lombok.*;
import org.apache.commons.lang3.StringUtils;

import java.util.Objects;

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

    // Provides all connection options needed for MPL or iFlow invocations.
    // Used by the testing tool;
    private ConnectionPropertiesContainer connectionPropertiesContainer;

    private MessageSendingAdditionalProperties messageSendingAdditionalProperties;

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

    public RequestContext createFromCurrentUsingConnectionPropertiesContainer() {
        ConnectionProperties connectionProperties = isDefaultRuntime()
            ? this.getConnectionPropertiesContainer().getConnectionPropertiesForPublicApi()
            : this.getConnectionPropertiesContainer().getConnectionPropertiesUsernameAndPassword();
        return this.toBuilder()
            .connectionProperties(connectionProperties)
            .connectionPropertiesContainer(null)
            .build();
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

    public boolean isDefaultRuntime() {
        return isDefaultRuntime(this.getRuntimeLocationId(), this.getDefaultRuntimeLocationId());
    }

    public static boolean isDefaultRuntime(String runtimeLocationId, String defaultRuntimeLocationId) {
        return StringUtils.isBlank(runtimeLocationId) || Objects.equals(runtimeLocationId, defaultRuntimeLocationId);
    }
}
