package com.figaf.integration.common.factory;

import com.figaf.integration.common.client.support.SapAirKeyHeaderInterceptor;
import com.github.markusbernhardt.proxy.ProxySearch;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpHost;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;
import org.apache.http.impl.conn.SystemDefaultRoutePlanner;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.client.support.BasicAuthenticationInterceptor;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.web.client.RestTemplate;

import java.net.ProxySelector;
import java.nio.charset.StandardCharsets;

/**
 * @author Arsenii Istlentev
 */
@Slf4j
@Getter
@ToString
public class HttpClientsFactory {

    private final boolean useProxyForConnections;
    private final int connectionRequestTimeout;
    private final int connectTimeout;
    private final int socketTimeout;
    private final boolean useForOnPremiseIntegration;
    private final String locationId;
    private final String sapAirKey;

    private OAuthHttpRequestInterceptor oAuthHttpRequestInterceptor;
    private SapAirKeyHeaderInterceptor sapAirKeyHeaderInterceptor;
    private DefaultProxyRoutePlanner defaultProxyRoutePlanner;

    public static HttpClientsFactory getForOnPremiseIntegration(
            boolean useProxyForConnections,
            int connectionRequestTimeout,
            int connectTimeout,
            int socketTimeout,
            String locationId,
            String sapAirKey
    ) {
        return new HttpClientsFactory(
                useProxyForConnections,
                connectionRequestTimeout,
                connectTimeout,
                socketTimeout,
                true,
                locationId,
                sapAirKey
        );
    }

    public static HttpClientsFactory getForOnCloudIntegration(
            boolean useProxyForConnections,
            int connectionRequestTimeout,
            int connectTimeout,
            int socketTimeout,
            String sapAirKey
    ) {
        return new HttpClientsFactory(
                useProxyForConnections,
                connectionRequestTimeout,
                connectTimeout,
                socketTimeout,
                false,
                null,
                sapAirKey
        );
    }

    public HttpClientsFactory() {
        this.useProxyForConnections = false;
        this.connectionRequestTimeout = 300000;
        this.connectTimeout = 300000;
        this.socketTimeout = 300000;
        this.useForOnPremiseIntegration = false;
        this.locationId = null;
        this.sapAirKey = null;
        this.oAuthHttpRequestInterceptor = null;
        this.defaultProxyRoutePlanner = null;
        this.sapAirKeyHeaderInterceptor = null;
    }

    public HttpClientsFactory(
            boolean useProxyForConnections,
            int connectionRequestTimeout,
            int connectTimeout,
            int socketTimeout
    ) {
        log.info("useProxyForConnections = {}", useProxyForConnections);
        this.useProxyForConnections = useProxyForConnections;
        this.connectionRequestTimeout = connectionRequestTimeout;
        this.connectTimeout = connectTimeout;
        this.socketTimeout = socketTimeout;
        this.useForOnPremiseIntegration = false;
        this.locationId = null;
        this.sapAirKey = null;
        this.sapAirKeyHeaderInterceptor = null;
        initProxy();
    }

    public HttpClientsFactory(
            boolean useProxyForConnections,
            int connectionRequestTimeout,
            int connectTimeout,
            int socketTimeout,
            String sapAirKey
    ) {
        log.info("useProxyForConnections = {}", useProxyForConnections);
        this.useProxyForConnections = useProxyForConnections;
        this.connectionRequestTimeout = connectionRequestTimeout;
        this.connectTimeout = connectTimeout;
        this.socketTimeout = socketTimeout;
        this.useForOnPremiseIntegration = false;
        this.locationId = null;
        this.sapAirKey = sapAirKey;
        this.sapAirKeyHeaderInterceptor = new SapAirKeyHeaderInterceptor(this.sapAirKey);
        initProxy();
    }

    public HttpClientsFactory(
            boolean useProxyForConnections,
            int connectionRequestTimeout,
            int connectTimeout,
            int socketTimeout,
            boolean useForOnPremiseIntegration,
            String locationId,
            String sapAirKey
    ) {
        log.info("useProxyForConnections = {}, useForOnPremiseIntegration = {}, locationId = {}", useProxyForConnections, useForOnPremiseIntegration, locationId);
        this.useProxyForConnections = useProxyForConnections;
        this.connectionRequestTimeout = connectionRequestTimeout;
        this.connectTimeout = connectTimeout;
        this.socketTimeout = socketTimeout;
        this.useForOnPremiseIntegration = useForOnPremiseIntegration;
        this.locationId = locationId;
        this.sapAirKey = sapAirKey;
        this.sapAirKeyHeaderInterceptor = new SapAirKeyHeaderInterceptor(this.sapAirKey);
        initProxy();
        applyCloudConnectorParameters(locationId);
    }

    private void initProxy() {
        if (this.useProxyForConnections) {
            // proxy config
            // Use the static factory method getDefaultProxySearch to create a proxy search instance
            // configured with the default proxy search strategies for the current environment.
            ProxySearch proxySearch = ProxySearch.getDefaultProxySearch();
            proxySearch.addStrategy(ProxySearch.Strategy.BROWSER);

            // Invoke the proxy search. This will create a ProxySelector with the detected proxy settings.
            ProxySelector proxySelector = proxySearch.getProxySelector();

            // Install this ProxySelector as default ProxySelector for all connections.
            if (proxySelector != null) {
                ProxySelector.setDefault(proxySelector);
                log.info("Proxy settings were found");
            } else {
                log.info("Proxy settings were not found");
            }
        }
    }

    private void applyCloudConnectorParameters(String locationId) {
        if (!this.useForOnPremiseIntegration) {
            this.oAuthHttpRequestInterceptor = null;
            this.defaultProxyRoutePlanner = null;
            return;
        }

        CloudConnectorParameters cloudConnectorParameters = CloudConnectorParameters.getInstance();
        if (cloudConnectorParameters == null) {
            this.oAuthHttpRequestInterceptor = null;
            this.defaultProxyRoutePlanner = null;
            return;
        }

        this.oAuthHttpRequestInterceptor = new OAuthHttpRequestInterceptor(cloudConnectorParameters, locationId);

        HttpHost proxy = new HttpHost(cloudConnectorParameters.getConnectionProxyHost(), cloudConnectorParameters.getConnectionProxyPort());
        this.defaultProxyRoutePlanner = new DefaultProxyRoutePlanner(proxy);

        log.info("CloudConnectorParameters are applied: {}", cloudConnectorParameters);
    }

    public HttpClientBuilder getHttpClientBuilder() {
        return getHttpClientBuilder(false);
    }

    public HttpClientBuilder getHttpClientBuilder(boolean disableRedirect) {
        HttpClientBuilder httpClientBuilder = HttpClients.custom();
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectionRequestTimeout(connectionRequestTimeout)
                .setConnectTimeout(connectTimeout)
                .setSocketTimeout(socketTimeout)
                .setCookieSpec(CookieSpecs.STANDARD)
                .build();
        httpClientBuilder.setDefaultRequestConfig(requestConfig);
        if (useProxyForConnections) {
            httpClientBuilder.setRoutePlanner(new SystemDefaultRoutePlanner(ProxySelector.getDefault()));
        }
        if (useForOnPremiseIntegration) {
            httpClientBuilder.addInterceptorFirst(oAuthHttpRequestInterceptor);
            httpClientBuilder.setRoutePlanner(defaultProxyRoutePlanner);
        }
        if (disableRedirect) {
            httpClientBuilder.disableRedirectHandling();
        }
        if (sapAirKeyHeaderInterceptor != null) {
            httpClientBuilder.addInterceptorFirst(sapAirKeyHeaderInterceptor);
        }
        return httpClientBuilder;
    }

    public HttpClientBuilder getHttpClientBuilder(SSLConnectionSocketFactory sslConnectionSocketFactory) {
        HttpClientBuilder httpClientBuilder = getHttpClientBuilder();
        return httpClientBuilder.setSSLSocketFactory(sslConnectionSocketFactory);
    }

    public HttpClient createHttpClient() {
        return createHttpClient(false);
    }

    public HttpClient createHttpClient(boolean disableRedirect) {
        return getHttpClientBuilder(disableRedirect).build();
    }

    public HttpClient createHttpClient(SSLConnectionSocketFactory sslConnectionSocketFactory) {
        return getHttpClientBuilder(sslConnectionSocketFactory).build();
    }

    public HttpComponentsClientHttpRequestFactory getHttpComponentsClientHttpRequestFactory() {
        return getHttpComponentsClientHttpRequestFactory(false);
    }

    public HttpComponentsClientHttpRequestFactory getHttpComponentsClientHttpRequestFactory(boolean disableRedirect) {
        return new CustomHttpComponentsClientHttpRequestFactory(createHttpClient(disableRedirect));
    }

    public RestTemplate createRestTemplate(BasicAuthenticationInterceptor basicAuthenticationInterceptor) {
        RestTemplate restTemplate = new RestTemplate(getHttpComponentsClientHttpRequestFactory());
        restTemplate.getInterceptors().add(basicAuthenticationInterceptor);
        restTemplate.getMessageConverters().add(0, new StringHttpMessageConverter(StandardCharsets.UTF_8));
        return restTemplate;
    }

    public RestTemplate createRestTemplate() {
        RestTemplate restTemplate = new RestTemplate(getHttpComponentsClientHttpRequestFactory());
        restTemplate.getMessageConverters().add(0, new StringHttpMessageConverter(StandardCharsets.UTF_8));
        return restTemplate;
    }

}
