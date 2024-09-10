package com.figaf.integration.common.factory;

import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.tokenflows.TokenFlowException;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.hc.core5.http.EntityDetails;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpRequestInterceptor;
import org.apache.hc.core5.http.protocol.HttpContext;

import java.time.Instant;

/**
 * @author Arsenii Istlentev
 */
@Slf4j
class OAuthHttpRequestInterceptor implements HttpRequestInterceptor {
    private final String locationId;
    private OAuth2TokenResponse oAuth2TokenResponse;
    private CloudConnectorAccessTokenProvider cloudConnectorAccessTokenProvider;

    public OAuthHttpRequestInterceptor(
        CloudConnectorParameters cloudConnectorParameters,
        String locationId
    ) {
        this.locationId = locationId;
        if (cloudConnectorParameters != null) {
            this.cloudConnectorAccessTokenProvider = new CloudConnectorAccessTokenProvider(cloudConnectorParameters);
        }
    }

    @Override
    public void process(HttpRequest request, EntityDetails details, HttpContext context) throws TokenFlowException {
        if (cloudConnectorAccessTokenProvider == null) {
            // environment is not recognized, skipping processing
            return;
        }

        synchronized (this) {
            if (oAuth2TokenResponse == null || (oAuth2TokenResponse.getExpiredAt() != null && oAuth2TokenResponse.getExpiredAt().isBefore(Instant.now()))) {
                oAuth2TokenResponse = cloudConnectorAccessTokenProvider.getToken();
            }
            request.addHeader("Proxy-Authorization", String.format("%s %s", "Bearer", oAuth2TokenResponse.getAccessToken()));
            if (StringUtils.isNotEmpty(locationId)) {
                request.addHeader("SAP-Connectivity-SCC-Location_ID", locationId);
            }
        }
    }
}
