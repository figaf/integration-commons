package com.figaf.integration.common.client.support;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.protocol.HttpContext;

@Slf4j
@RequiredArgsConstructor
public class SapAirKeyHeaderInterceptor implements HttpRequestInterceptor {

    private final static String APPLICATION_INTERFACE_KEY_HEADER = "Application-Interface-Key";

    private final String sapAirKey;

    @Override
    public void process(HttpRequest request, HttpContext context) {
        if (StringUtils.isNotEmpty(sapAirKey) && !request.containsHeader(APPLICATION_INTERFACE_KEY_HEADER)) {
            request.addHeader(APPLICATION_INTERFACE_KEY_HEADER, sapAirKey);
        }
    }

}
