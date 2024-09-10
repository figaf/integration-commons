package com.figaf.integration.common.factory;

import com.figaf.integration.common.enums.TypeOfService;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.EnumMap;
import java.util.Optional;

/**
 * @author Arsenii Istlentev
 */
@Getter
@Builder
@Slf4j
@ToString(of = {"xsuaaUrl", "connectionProxyHost", "connectionProxyPort", "connectionProxyPortSocks5"})
public class CloudConnectorParameters {

    private static final String SOCKS5_PROXY_PORT_PROPERTY = "onpremise_socks5_proxy_port";

    private static final String HTTP_PROXY_PORT_PROPERTY = "onpremise_proxy_http_port";

    private static final String HTTP_PROXY_HOST_PROPERTY = "onpremise_proxy_host";

    private static final CloudConnectorParameters INSTANCE;

    private String clientId;

    private String clientSecret;

    private String xsuaaUrl;

    private String connectionProxyHost;

    private int connectionProxyPort;

    private Integer connectionProxyPortSocks5;

    static {
        INSTANCE = init();
    }

    static CloudConnectorParameters getInstance() {
        return INSTANCE;
    }

    private static CloudConnectorParameters init() {
        JSONObject vcapServicesObj = createVcapServices();
        if (vcapServicesObj == null) {
            return null;
        }

        JSONArray xsuaaJsonArr = vcapServicesObj.optJSONArray("xsuaa");
        if (xsuaaJsonArr == null) {
            log.info("xsuaa is null");
            return null;
        }

        JSONObject xsuaaCredentials = xsuaaJsonArr.getJSONObject(0).getJSONObject("credentials");

        JSONArray connectivityJsonArr = vcapServicesObj.optJSONArray("connectivity");
        if (connectivityJsonArr == null) {
            log.info("connectivity is null");
            return null;
        }

        JSONObject connectivityCredentials = connectivityJsonArr.getJSONObject(0).getJSONObject("credentials");
        Integer connectionProxyPortSocks5 = connectivityCredentials.has(SOCKS5_PROXY_PORT_PROPERTY) ? Integer.valueOf(connectivityCredentials.getString(SOCKS5_PROXY_PORT_PROPERTY)) : null;

        // client id and client secret are no longer needed because integration is provided within XsuaaTokenFlows
        CloudConnectorParameters.CloudConnectorParametersBuilder cloudConnectorParametersBuilder = CloudConnectorParameters.builder()
            .clientId(connectivityCredentials.getString("clientid"))
            .clientSecret(connectivityCredentials.getString("clientsecret"))
            .xsuaaUrl(xsuaaCredentials.getString("url"))
            .connectionProxyHost(connectivityCredentials.getString(HTTP_PROXY_HOST_PROPERTY))
            .connectionProxyPort(Integer.parseInt(connectivityCredentials.getString(HTTP_PROXY_PORT_PROPERTY)));
        if (Optional.ofNullable(connectionProxyPortSocks5).isPresent()) {
            cloudConnectorParametersBuilder.connectionProxyPortSocks5(connectionProxyPortSocks5);
        }
        CloudConnectorParameters cloudConnectorParameters = cloudConnectorParametersBuilder.build();
        log.info("cloudConnectorParameters was successfully initialized: {}", cloudConnectorParameters);
        return cloudConnectorParameters;
    }

    public static EnumMap<TypeOfService, Boolean> checkServicesExistence() {
        JSONObject vcapServicesObj = createVcapServices();
        if (vcapServicesObj == null) {
            return null;
        }

        EnumMap<TypeOfService, Boolean> servicesExistence = new EnumMap<>(TypeOfService.class);
        servicesExistence.put(TypeOfService.CONNECTIVITY, checkService(vcapServicesObj, "connectivity"));
        servicesExistence.put(TypeOfService.DESTINATION, checkService(vcapServicesObj, "destination"));
        return servicesExistence;
    }

    private static JSONObject createVcapServices() {
        String vcapServices = System.getenv("VCAP_SERVICES");
        if (StringUtils.isEmpty(vcapServices)) {
            log.info("VCAP_SERVICES is null");
            return null;
        }
        return new JSONObject(vcapServices);
    }

    private static boolean checkService(JSONObject vcapServicesObj, String serviceName) {
        JSONArray serviceArray = vcapServicesObj.optJSONArray(serviceName);
        boolean exists = serviceArray != null;
        if (!exists) {
            log.info("{} is null", serviceName);
        }
        return exists;
    }
}
