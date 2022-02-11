package com.figaf.integration.common.factory;

import lombok.Builder;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * @author Arsenii Istlentev
 */
@Builder
@Slf4j
@ToString(of = {"xsuaaUrl", "connectionProxyHost", "connectionProxyPort"})
class CloudConnectorParameters {

    private final static CloudConnectorParameters INSTANCE;

    @Getter
    private String clientId;

    @Getter
    private String clientSecret;

    @Getter
    private String xsuaaUrl;

    @Getter
    private String connectionProxyHost;

    @Getter
    private int connectionProxyPort;

    static {
        INSTANCE = init();
    }

    static CloudConnectorParameters getInstance() {
        return INSTANCE;
    }

    private static CloudConnectorParameters init() {
        String vcapServices = System.getenv("VCAP_SERVICES");
        if (StringUtils.isEmpty(vcapServices)) {
            log.info("VCAP_SERVICES is null");
            return null;
        }

        JSONObject jsonObj = new JSONObject(vcapServices);

        JSONArray xsuaaJsonArr = jsonObj.optJSONArray("xsuaa");
        if (xsuaaJsonArr == null) {
            log.info("xsuaa is null");
            return null;
        }

        JSONObject xsuaaCredentials = xsuaaJsonArr.getJSONObject(0).getJSONObject("credentials");

        JSONArray connectivityJsonArr = jsonObj.optJSONArray("connectivity");
        if (connectivityJsonArr == null) {
            log.info("connectivity is null");
            return null;
        }

        JSONObject connectivityCredentials = connectivityJsonArr.getJSONObject(0).getJSONObject("credentials");
        CloudConnectorParameters cloudConnectorParameters = CloudConnectorParameters.builder()
                .clientId(connectivityCredentials.getString("clientid"))
                .clientSecret(connectivityCredentials.getString("clientsecret"))
                .xsuaaUrl(xsuaaCredentials.getString("url"))
                .connectionProxyHost(connectivityCredentials.getString("onpremise_proxy_host"))
                .connectionProxyPort(Integer.parseInt(connectivityCredentials.getString("onpremise_proxy_http_port")))
                .build();

        log.info("cloudConnectorParameters was successfully initialized: {}", cloudConnectorParameters);
        return cloudConnectorParameters;
    }

}
