package com.figaf.integration.common.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.apache.hc.client5.http.classic.HttpClient;
import org.springframework.web.client.RestTemplate;

/**
 * @author Arsenii Istlentev
 */
@AllArgsConstructor
@Getter
@Setter
public class RestTemplateWrapper {

    private RestTemplate restTemplate;
    private HttpClient httpClient;
}
