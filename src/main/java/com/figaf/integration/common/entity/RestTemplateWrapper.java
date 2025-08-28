package com.figaf.integration.common.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.cookie.CookieStore;
import org.springframework.web.client.RestTemplate;

/**
 * @author Arsenii Istlentev
 */
@AllArgsConstructor
@Getter
public class RestTemplateWrapper {

    private final RestTemplate restTemplate;
    private final HttpClient httpClient;
    private final CookieStore cookieStore;
}
