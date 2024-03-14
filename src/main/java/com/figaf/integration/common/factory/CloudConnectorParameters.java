package com.figaf.integration.common.factory;

import lombok.Builder;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Optional;

/**
 * @author Arsenii Istlentev
 */
@Getter
@Builder
@Slf4j
@ToString(of = {"xsuaaUrl", "connectionProxyHost", "connectionProxyPort", "connectionProxyPortSocks5"})
class CloudConnectorParameters {

    private static final String SOCKS5_PROXY_PORT_PROPERTY = "onpremise_socks5_proxy_port";

    private static final String HTTP_PROXY_PORT_PROPERTY = "onpremise_proxy_http_port";

    private static final String HTTP_PROXY_HOST_PROPERTY = "onpremise_proxy_host";

    private final static CloudConnectorParameters INSTANCE;

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
        Integer connectionProxyPortSocks5 = connectivityCredentials.has(SOCKS5_PROXY_PORT_PROPERTY) ? Integer.valueOf(connectivityCredentials.getString(SOCKS5_PROXY_PORT_PROPERTY)) : null;

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

}
