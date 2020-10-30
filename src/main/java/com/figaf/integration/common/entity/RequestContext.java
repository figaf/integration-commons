package com.figaf.integration.common.entity;

import lombok.*;

/**
 * @author Arsenii Istlentev
 */
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@ToString
public class RequestContext {

    private ConnectionProperties connectionProperties;
    private CloudPlatformType cloudPlatformType;
    private Platform platform;
    private String restTemplateWrapperKey;

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
}
