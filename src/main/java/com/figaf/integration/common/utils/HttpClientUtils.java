package com.figaf.integration.common.utils;

import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;

import java.io.IOException;

@Slf4j
public class HttpClientUtils {

    public static void closeQuietly(HttpClient httpClient) {
        if (httpClient instanceof CloseableHttpClient client) {
            try {
                client.close();
            } catch (IOException ex) {
                log.error("Couldn't close http client: " + ex.getMessage(), ex);
            }
        }
    }
}
