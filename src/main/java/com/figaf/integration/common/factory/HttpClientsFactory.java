package com.figaf.integration.common.factory;

import com.figaf.integration.common.client.support.RestrictedRedirectStrategy;
import com.figaf.integration.common.client.support.SapAirKeyHeaderInterceptor;
import com.figaf.integration.common.entity.RequestContext;
import com.github.markusbernhardt.proxy.ProxySearch;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.config.TlsConfig;
import org.apache.hc.client5.http.cookie.StandardCookieSpec;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.impl.routing.DefaultProxyRoutePlanner;
import org.apache.hc.client5.http.impl.routing.SystemDefaultRoutePlanner;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.io.SocketConfig;
import org.apache.hc.core5.http.ssl.TLS;
import org.apache.hc.core5.pool.PoolConcurrencyPolicy;
import org.apache.hc.core5.pool.PoolReusePolicy;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.ssl.SSLContexts;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.client.support.BasicAuthenticationInterceptor;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import java.io.ByteArrayInputStream;
import java.net.ProxySelector;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import static java.lang.String.format;

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
    private final boolean useForBtpToOnPremiseIntegration;
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

    public static HttpClientsFactory getForCloudIntegration(
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
        this.useForBtpToOnPremiseIntegration = false;
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
        this.useForBtpToOnPremiseIntegration = false;
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
        this.useForBtpToOnPremiseIntegration = false;
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
        boolean useForBtpToOnPremiseIntegration,
        String locationId,
        String sapAirKey
    ) {
        log.info("useProxyForConnections = {}, useForBtpToOnPremiseIntegration = {}, locationId = {}",
            useProxyForConnections, useForBtpToOnPremiseIntegration, locationId
        );
        this.useProxyForConnections = useProxyForConnections;
        this.connectionRequestTimeout = connectionRequestTimeout;
        this.connectTimeout = connectTimeout;
        this.socketTimeout = socketTimeout;
        this.useForBtpToOnPremiseIntegration = useForBtpToOnPremiseIntegration;
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
        if (!this.useForBtpToOnPremiseIntegration) {
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

    public HttpClientBuilder getHttpClientBuilder(boolean disableRedirect) {
        return getHttpClientBuilder(
            null,
            0,
            0,
            disableRedirect,
            false
        );
    }

    public HttpClientBuilder getHttpClientBuilder(SSLConnectionSocketFactory sslConnectionSocketFactory) {
        return getHttpClientBuilder(sslConnectionSocketFactory, 0, 0, false, false);
    }

    public HttpClientBuilder getHttpClientBuilder(
        SSLConnectionSocketFactory sslConnectionSocketFactory,
        int maxConnPerRoute,
        int maxConnTotal,
        boolean disableRedirect,
        boolean omitCloudConnectorProxy
    ) {
        PoolingHttpClientConnectionManager connectionManager = PoolingHttpClientConnectionManagerBuilder.create()
            .setSSLSocketFactory(sslConnectionSocketFactory)
            .setDefaultTlsConfig(TlsConfig.custom()
                .setHandshakeTimeout(Timeout.ofMilliseconds(socketTimeout))
                .setSupportedProtocols(TLS.V_1_2, TLS.V_1_3) // At that point of code, we didn't have a problem when we had only TLS 1.3 but some SAP services may require TLS 1.2
                .build())
            .setDefaultSocketConfig(SocketConfig.custom()
                .setSoTimeout(Timeout.ofMilliseconds(socketTimeout))
                .build())
            .setPoolConcurrencyPolicy(PoolConcurrencyPolicy.STRICT)
            .setConnPoolPolicy(PoolReusePolicy.LIFO)
            .setMaxConnPerRoute(maxConnPerRoute)
            .setMaxConnTotal(maxConnTotal)
            .setDefaultConnectionConfig(ConnectionConfig.custom()
                .setSocketTimeout(Timeout.ofMilliseconds(socketTimeout))
                .setConnectTimeout(Timeout.ofMilliseconds(connectTimeout))
                .setTimeToLive(TimeValue.ofMinutes(10))
                .build())
            .build();

        HttpClientBuilder httpClientBuilder = HttpClients.custom()
            .setConnectionManager(connectionManager);
        RequestConfig requestConfig = RequestConfig.custom()
            .setConnectionRequestTimeout(Timeout.ofMilliseconds(connectionRequestTimeout))
            .setCookieSpec(StandardCookieSpec.STRICT)
            .build();
        httpClientBuilder.setDefaultRequestConfig(requestConfig);
        httpClientBuilder.setRedirectStrategy(RestrictedRedirectStrategy.INSTANCE);
        if (useProxyForConnections) {
            httpClientBuilder.setRoutePlanner(new SystemDefaultRoutePlanner(ProxySelector.getDefault()));
        }
        if (useForBtpToOnPremiseIntegration && CloudConnectorParameters.getInstance() != null) {
            httpClientBuilder.addRequestInterceptorFirst(oAuthHttpRequestInterceptor);
            if (!omitCloudConnectorProxy) {
                httpClientBuilder.setRoutePlanner(defaultProxyRoutePlanner);
            }
        }
        if (disableRedirect) {
            httpClientBuilder.disableRedirectHandling();
        }
        if (sapAirKeyHeaderInterceptor != null) {
            httpClientBuilder.addRequestInterceptorFirst(sapAirKeyHeaderInterceptor);
        }
        return httpClientBuilder;
    }


    public HttpClient createHttpClient() {
        return createHttpClient(false, false, false);
    }

    public HttpClient createHttpClient(boolean disableRedirect, boolean initDefaultSslConnectionSocketFactory, boolean omitCloudConnectorProxy) {
        SSLConnectionSocketFactory defaultFactory = null;
        if (initDefaultSslConnectionSocketFactory) {
            defaultFactory = SSLConnectionSocketFactoryBuilder.create()
                .setSslContext(SSLContexts.createSystemDefault())
                .setTlsVersions(TLS.V_1_2, TLS.V_1_3) // At that point of code, we didn't have a problem when we had only TLS 1.3 but some SAP services may require TLS 1.2
                .build();
        }
        return getHttpClientBuilder(
            defaultFactory,
            0,
            0,
            disableRedirect,
            omitCloudConnectorProxy
        ).build();
    }

    public HttpClient createHttpClient(byte[] certificate, String certificatePassword) {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (ByteArrayInputStream keyStoreInput = new ByteArrayInputStream(certificate)) {
                keyStore.load(keyStoreInput, certificatePassword.toCharArray());
            }

            SSLContext sslContext = SSLContextBuilder.create()
                .loadKeyMaterial(keyStore, certificatePassword.toCharArray())
                .build();

            SSLConnectionSocketFactory sslConnectionSocketFactory = SSLConnectionSocketFactoryBuilder.create()
                .setSslContext(sslContext)
                .setTlsVersions(TLS.V_1_2, TLS.V_1_3) //SAP Passport authentication works only with TLS 1.2
                .build();

            return getHttpClientBuilder(sslConnectionSocketFactory).build();
        } catch (Exception ex) {
            log.error("Can't create httpClient with SAP Passport certificate: ", ex);
            throw new RuntimeException(format("Can't create httpClient with SAP Passport certificate: %s", ExceptionUtils.getMessage(ex)));
        }
    }

    public HttpClient createHttpClient(SSLConnectionSocketFactory sslConnectionSocketFactory) {
        return getHttpClientBuilder(sslConnectionSocketFactory).build();
    }

    public HttpClient createHttpClient(SSLConnectionSocketFactory sslConnectionSocketFactory, boolean disableRedirect) {
        return getHttpClientBuilder(sslConnectionSocketFactory, 0, 0, disableRedirect, false).build();
    }

    public HttpClient createHttpClient(
        SSLConnectionSocketFactory sslConnectionSocketFactory,
        int maxConnPerRoute,
        int maxConnTotal,
        boolean disableRedirect
    ) {
        return getHttpClientBuilder(sslConnectionSocketFactory, maxConnPerRoute, maxConnTotal, disableRedirect, false).build();
    }

    public HttpComponentsClientHttpRequestFactory getHttpComponentsClientHttpRequestFactory() {
        return getHttpComponentsClientHttpRequestFactory(false, false, false);
    }

    public HttpComponentsClientHttpRequestFactory getHttpComponentsClientHttpRequestFactory(boolean omitCloudConnectorProxy) {
        return getHttpComponentsClientHttpRequestFactory(false, false, omitCloudConnectorProxy);
    }

    public HttpComponentsClientHttpRequestFactory getHttpComponentsClientHttpRequestFactory(
        boolean disableRedirect,
        boolean initDefaultSslConnectionSocketFactory,
        boolean omitCloudConnectorProxy
    ) {
        return new HttpComponentsClientHttpRequestFactory(
            createHttpClient(disableRedirect, initDefaultSslConnectionSocketFactory, omitCloudConnectorProxy)
        );
    }

    public HttpComponentsClientHttpRequestFactory getHttpComponentsClientHttpRequestFactory(RequestContext requestContext) {
        if (requestContext.isUseSapPassport()) {
            return new HttpComponentsClientHttpRequestFactory(
                createHttpClient(requestContext.getCertificate(), requestContext.getCertificatePassword())
            );
        } else {
            return new HttpComponentsClientHttpRequestFactory(
                createHttpClient()
            );
        }
    }

    public RestTemplate createRestTemplate(BasicAuthenticationInterceptor basicAuthenticationInterceptor) {
        RestTemplate restTemplate = new RestTemplate(getHttpComponentsClientHttpRequestFactory());
        restTemplate.getInterceptors().add(basicAuthenticationInterceptor);
        restTemplate.getMessageConverters().add(0, new StringHttpMessageConverter(StandardCharsets.UTF_8));
        return restTemplate;
    }

    public RestTemplate createRestTemplate(boolean omitCloudConnectorProxy) {
        RestTemplate restTemplate = new RestTemplate(getHttpComponentsClientHttpRequestFactory(omitCloudConnectorProxy));
        restTemplate.getMessageConverters().add(0, new StringHttpMessageConverter(StandardCharsets.UTF_8));
        return restTemplate;
    }
}
