package com.figaf.integration.common.factory;

import com.github.markusbernhardt.proxy.ProxySearch;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.SystemDefaultRoutePlanner;
import org.springframework.http.client.ClientHttpRequestInterceptor;
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

    public HttpClientsFactory() {
        this.useProxyForConnections = false;
        this.connectionRequestTimeout = 300000;
        this.connectTimeout = 300000;
        this.socketTimeout = 300000;
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

    public HttpClientBuilder getHttpClientBuilder() {
        HttpClientBuilder httpClientBuilder = HttpClients.custom();
        RequestConfig requestConfig = RequestConfig.custom()
            .setConnectionRequestTimeout(connectionRequestTimeout)
            .setConnectTimeout(connectTimeout)
            .setSocketTimeout(socketTimeout)
            .build();
        httpClientBuilder.setDefaultRequestConfig(requestConfig);
        if (this.useProxyForConnections) {
            return httpClientBuilder.setRoutePlanner(new SystemDefaultRoutePlanner(ProxySelector.getDefault()));
        } else {
            return httpClientBuilder;
        }
    }

    public HttpClientBuilder getHttpClientBuilder(SSLConnectionSocketFactory sslConnectionSocketFactory) {
        HttpClientBuilder httpClientBuilder = getHttpClientBuilder();
        return httpClientBuilder.setSSLSocketFactory(sslConnectionSocketFactory);
    }

    public HttpClient createHttpClient() {
        return getHttpClientBuilder().build();
    }

    public HttpClient createHttpClient(SSLConnectionSocketFactory sslConnectionSocketFactory) {
        return getHttpClientBuilder(sslConnectionSocketFactory).build();
    }

    public HttpComponentsClientHttpRequestFactory getHttpComponentsClientHttpRequestFactory() {
        return new HttpComponentsClientHttpRequestFactory(createHttpClient());
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
