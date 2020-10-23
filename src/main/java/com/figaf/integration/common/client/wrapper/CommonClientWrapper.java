package com.figaf.integration.common.client.wrapper;

import com.figaf.integration.common.entity.*;
import com.figaf.integration.common.exception.ClientIntegrationException;
import com.figaf.integration.common.utils.RestTemplateWrapperHelper;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.springframework.http.*;
import org.springframework.http.client.support.BasicAuthenticationInterceptor;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author Arsenii Istlentev
 */
@Slf4j
@AllArgsConstructor
public class CommonClientWrapper {

    private final static int MAX_NUMBER_OF_AUTH_ATTEMPTS = 4;
    private final static Pattern LOCATION_URL_PATTERN = Pattern.compile(".*location=\"(.*)\"<\\/script>.*");
    private final static Pattern SIGNATURE_PATTERN = Pattern.compile(".*signature=(.*);path.*");
    private final static Pattern LOGIN_URL_PATTERN = Pattern.compile(".*<meta name=\"redirect\"[\\s\\S]*content=\"(.*)\">");

    private final String ssoUrl;

    public interface ResponseHandlerCallbackForReadMethods<R, T> {
        R apply(T resolvedBody) throws Exception;
    }

    public interface ResponseHandlerCallbackForCrudMethods<R> {
        R apply(String url, String token, RestTemplateWrapper restTemplateWrapper);
    }

    public <R> R executeGet(CommonClientWrapperEntity commonClientWrapperEntity, String path, ResponseHandlerCallbackForReadMethods<R, String> responseHandlerCallback) {
        return executeGet(commonClientWrapperEntity, path, responseHandlerCallback, String.class);
    }

    public <R, T> R executeGet(CommonClientWrapperEntity commonClientWrapperEntity, String path, ResponseHandlerCallbackForReadMethods<R, T> responseHandlerCallback, Class<T> bodyType) {
        T responseBody;
        if (CloudPlatformType.CLOUD_FOUNDRY.equals(commonClientWrapperEntity.getCloudPlatformType())) {
            ResponseEntity<T> initialResponseEntity = executeGetRequestReturningTextBody(commonClientWrapperEntity, path, bodyType);
            responseBody = makeAuthRequestsAndReturnNeededBody(commonClientWrapperEntity, path, initialResponseEntity, bodyType);
        } else {
            responseBody = executeGetRequestWithBasicAuthReturningTextBody(commonClientWrapperEntity, path, bodyType);
        }

        R response;
        try {
            response = responseHandlerCallback.apply(responseBody);
        } catch (Exception ex) {
            log.error("Can't handle response body: ", ex);
            throw new ClientIntegrationException(ex);
        }

        return response;
    }

    public <R> R executeMethod(CommonClientWrapperEntity commonClientWrapperEntity, String pathForMainRequest, ResponseHandlerCallbackForCrudMethods<R> responseHandlerCallback) {
        return executeMethod(commonClientWrapperEntity, "/itspaces/api/1.0/user", pathForMainRequest, responseHandlerCallback);
    }

    public <R> R executeMethod(CommonClientWrapperEntity commonClientWrapperEntity, String pathForToken, String pathForMainRequest, ResponseHandlerCallbackForCrudMethods<R> responseHandlerCallback) {
        try {
            if (CloudPlatformType.CLOUD_FOUNDRY.equals(commonClientWrapperEntity.getCloudPlatformType())) {
                RestTemplateWrapper restTemplateWrapper = RestTemplateWrapperHelper.getOrCreateRestTemplateWrapperSingleton(commonClientWrapperEntity.getRestTemplateWrapperKey());
                String token = retrieveToken(commonClientWrapperEntity, restTemplateWrapper.getRestTemplate(), pathForToken);
                String url = buildUrl(commonClientWrapperEntity, pathForMainRequest);
                return responseHandlerCallback.apply(url, token, RestTemplateWrapperHelper.getOrCreateRestTemplateWrapperSingleton(commonClientWrapperEntity.getRestTemplateWrapperKey()));
            } else {
                ConnectionProperties connectionProperties = commonClientWrapperEntity.getConnectionProperties();
                RestTemplateWrapper restTemplateWrapper = RestTemplateWrapperHelper.createRestTemplateWrapper(new BasicAuthenticationInterceptor(connectionProperties.getUsername(), connectionProperties.getPassword()));
                String token = retrieveToken(commonClientWrapperEntity, restTemplateWrapper.getRestTemplate(), pathForToken);
                String url = buildUrl(commonClientWrapperEntity, pathForMainRequest);
                return responseHandlerCallback.apply(url, token, restTemplateWrapper);
            }
        } catch (Exception ex) {
            log.error("Can't executeMethod: ", ex);
            throw new ClientIntegrationException(ex);
        }
    }

    private String retrieveToken(CommonClientWrapperEntity commonClientWrapperEntity, RestTemplate restTemplate) {
        return retrieveToken(commonClientWrapperEntity, restTemplate, "/itspaces/api/1.0/user");
    }

    private String retrieveToken(CommonClientWrapperEntity commonClientWrapperEntity, RestTemplate restTemplate, String path) {
        try {
            ConnectionProperties connectionProperties = commonClientWrapperEntity.getConnectionProperties();
            String url = buildUrl(connectionProperties, path);
            ResponseEntity<String> responseEntity;
            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.add("X-CSRF-Token", "Fetch");
            if (CloudPlatformType.CLOUD_FOUNDRY.equals(commonClientWrapperEntity.getCloudPlatformType())) {
                RequestEntity requestEntity = new RequestEntity(httpHeaders, HttpMethod.GET, new URI(url));
                ResponseEntity<String> initialResponseEntity = restTemplate.exchange(requestEntity, String.class);
                if (!HttpStatus.OK.equals(initialResponseEntity.getStatusCode()) || initialResponseEntity.getBody() != null) {
                    responseEntity = makeAuthRequestsAndReturnResponseEntity(commonClientWrapperEntity, path, initialResponseEntity, httpHeaders, String.class, 1);
                } else {
                    responseEntity = initialResponseEntity;
                }
            } else {
                RequestEntity requestEntity = new RequestEntity(httpHeaders, HttpMethod.GET, new URI(url));
                responseEntity = restTemplate.exchange(requestEntity, String.class);
            }

            if (responseEntity == null) {
                throw new ClientIntegrationException(String.format("Couldn't fetch token for user %s: response is null.", connectionProperties.getUsername()));
            }

            if (!HttpStatus.OK.equals(responseEntity.getStatusCode())) {
                throw new ClientIntegrationException(String.format(
                        "Couldn't fetch token for user: Code: %d, Message: %s",
                        responseEntity.getStatusCode().value(),
                        responseEntity.getBody())
                );
            }

            String token = responseEntity.getHeaders().getFirst("X-CSRF-Token");
            return token;
        } catch (Exception ex) {
            log.error("Can't retrieveToken: ", ex);
            throw new ClientIntegrationException(ex);
        }
    }

    private String buildUrl(CommonClientWrapperEntity commonClientWrapperEntity, String path) {
        return buildUrl(commonClientWrapperEntity.getConnectionProperties(), path);
    }

    private String buildUrl(ConnectionProperties connectionProperties, String path) {
        return String.format("%s%s", connectionProperties.getUrlRemovingDefaultPortIfNecessary(), path);
    }

    private RestTemplateWrapper getRestTemplateWrapper(CommonClientWrapperEntity commonClientWrapperEntity) {
        ConnectionProperties connectionProperties = commonClientWrapperEntity.getConnectionProperties();
        RestTemplateWrapper restTemplateWrapper;
        if (CloudPlatformType.CLOUD_FOUNDRY.equals(commonClientWrapperEntity.getCloudPlatformType())) {
            restTemplateWrapper = RestTemplateWrapperHelper.getOrCreateRestTemplateWrapperSingleton(commonClientWrapperEntity.getRestTemplateWrapperKey());
        } else {
            restTemplateWrapper = RestTemplateWrapperHelper.createRestTemplateWrapper(new BasicAuthenticationInterceptor(connectionProperties.getUsername(), connectionProperties.getPassword()));
        }
        return restTemplateWrapper;
    }

    private <T> ResponseEntity<T> executeGetRequestReturningTextBody(CommonClientWrapperEntity commonClientWrapperEntity, String path, Class<T> bodyType) {
        ConnectionProperties connectionProperties = commonClientWrapperEntity.getConnectionProperties();
        final String url = buildUrl(connectionProperties, path);
        try {
            RequestEntity requestEntity = new RequestEntity(HttpMethod.GET, new URI(url));
            RestTemplateWrapper restTemplateWrapper = RestTemplateWrapperHelper.getOrCreateRestTemplateWrapperSingleton(commonClientWrapperEntity.getRestTemplateWrapperKey());
            ResponseEntity<T> responseEntity = restTemplateWrapper.getRestTemplate().exchange(requestEntity, bodyType);
            return responseEntity;
        } catch (Exception ex) {
            String errorMessage = String.format("Can't execute GET request %s successfully: ", url);
            log.error(errorMessage, ex);
            throw new ClientIntegrationException(errorMessage, ex);
        }
    }

    private <T> T executeGetRequestWithBasicAuthReturningTextBody(CommonClientWrapperEntity commonClientWrapperEntity, String path, Class<T> bodyType) {
        ConnectionProperties connectionProperties = commonClientWrapperEntity.getConnectionProperties();
        final String url = buildUrl(connectionProperties, path);
        try {
            RestTemplate restTemplateWithBasicAuth = RestTemplateWrapperHelper.createRestTemplate(new BasicAuthenticationInterceptor(connectionProperties.getUsername(), connectionProperties.getPassword()));
            RequestEntity requestEntity = new RequestEntity(HttpMethod.GET, new URI(url));
            ResponseEntity<T> responseEntity = restTemplateWithBasicAuth.exchange(requestEntity, bodyType);
            return responseEntity.getBody();
        } catch (Exception ex) {
            String errorMessage = String.format("Can't execute GET request %s successfully: ", url);
            log.error(errorMessage, ex);
            throw new ClientIntegrationException(errorMessage, ex);
        }
    }

    private <T> T makeAuthRequestsAndReturnNeededBody(CommonClientWrapperEntity commonClientWrapperEntity, String path, ResponseEntity<T> initialResponseEntity, Class<T> responseType) {
        ResponseEntity<T> responseEntity = makeAuthRequestsAndReturnResponseEntity(commonClientWrapperEntity, path, initialResponseEntity, null, responseType, 1);
        return responseEntity.getBody();
    }

    private <T> ResponseEntity<T> makeAuthRequestsAndReturnResponseEntity(
            CommonClientWrapperEntity commonClientWrapperEntity,
            String path,
            ResponseEntity<T> initialResponseEntity,
            HttpHeaders additionalHeaders,
            Class<T> responseType,
            int numberOfAttempts
    ) {
        try {
            String responseBodyString = getResponseBodyString(initialResponseEntity);

            String authorizationUrl = retrieveAuthorizationUrl(responseBodyString);
            if (authorizationUrl == null) {
                return initialResponseEntity;
            }

            String signature = retrieveSignature(responseBodyString);

            String commonClientWrapperEntityId = commonClientWrapperEntity.getRestTemplateWrapperKey();

            String loginPageUrl = getLoginPageUrlFromAuthorizationPage(commonClientWrapperEntityId, authorizationUrl);

            String loginPageContent = getLoginPageContent(commonClientWrapperEntityId, loginPageUrl);

            MultiValueMap<String, String> loginFormData = buildLoginFormData(commonClientWrapperEntity, loginPageContent);
            String redirectUrlReceivedAfterSuccessfulAuthorization = authorize(commonClientWrapperEntityId, loginFormData);

            ResponseEntity<T> result = executeRedirectRequestAfterSuccessfulAuthorization(commonClientWrapperEntityId, redirectUrlReceivedAfterSuccessfulAuthorization, path, signature, additionalHeaders, responseType);

            log.debug("number of attempts = {}", numberOfAttempts);

            return result;
        } catch (HttpClientErrorException ex) {
            //sometimes authorization requests fail due to unclear reason. That's why we need to do another attempt.
            if ((HttpStatus.BAD_REQUEST.equals(ex.getStatusCode()) || HttpStatus.INTERNAL_SERVER_ERROR.equals(ex.getStatusCode()) && Platform.API_MANAGEMENT.equals(commonClientWrapperEntity.getPlatform())) &&
                    numberOfAttempts < MAX_NUMBER_OF_AUTH_ATTEMPTS
            ) {
                log.warn("HttpClientErrorException occurs: {}, {}", ex.getStatusCode(), ex.getMessage());
                return makeAuthRequestsAndReturnResponseEntity(commonClientWrapperEntity, path, initialResponseEntity, additionalHeaders, responseType, numberOfAttempts + 1);
            } else {
                throw ex;
            }
        } catch (Exception ex) {
            String errorMessage = String.format("Can't authorize and execute initial request on %s", path);
            log.error(errorMessage, ex);
            throw new ClientIntegrationException(errorMessage, ex);
        }
    }

    private String getLoginPageUrlFromAuthorizationPage(String commonClientWrapperEntityId, String url) throws URISyntaxException {
        log.debug("#getLoginPageUrlFromAuthorizationPage(String commonClientWrapperEntityId, String url): {}, {}", commonClientWrapperEntityId, url);
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9");
        RequestEntity requestEntity = new RequestEntity(httpHeaders, HttpMethod.GET, new URI(url));

        RestTemplateWrapper restTemplateWrapper = RestTemplateWrapperHelper.getOrCreateRestTemplateWrapperSingleton(commonClientWrapperEntityId);
        ResponseEntity<String> responseEntity;
        try {
            responseEntity = restTemplateWrapper.getRestTemplate().exchange(requestEntity, String.class);
        } catch (HttpClientErrorException ex) {
            if (HttpStatus.BAD_REQUEST.equals(ex.getStatusCode())) {
                restTemplateWrapper = RestTemplateWrapperHelper.createNewRestTemplateWrapper(commonClientWrapperEntityId);
                responseEntity = restTemplateWrapper.getRestTemplate().exchange(requestEntity, String.class);
            } else {
                throw ex;
            }
        }
        String loginPageUrl = retrieveLoginPageUrl(responseEntity.getBody());
        if (loginPageUrl == null) {
            throw new ClientIntegrationException(String.format("Can't retrieve login page url from %s", responseEntity.getBody()));
        }

        return loginPageUrl.replaceAll("amp;", "");
    }

    private String getLoginPageContent(String commonClientWrapperEntityId, String url) throws Exception {
        log.debug("#getLoginPageContent(String commonClientWrapperEntityId, String url): {}, {}", commonClientWrapperEntityId, url);
        RequestEntity requestEntity = new RequestEntity(HttpMethod.GET, new URI(url));
        RestTemplateWrapper restTemplateWrapper = RestTemplateWrapperHelper.getOrCreateRestTemplateWrapperSingleton(commonClientWrapperEntityId);
        ResponseEntity<String> exchange = restTemplateWrapper.getRestTemplate().exchange(requestEntity, String.class);
        return exchange.getBody();
    }

    private String authorize(String commonClientWrapperEntityId, MultiValueMap<String, String> map) {
        log.debug("#authorize(String commonClientWrapperEntityId, MultiValueMap<String, String> map): {}, ssoUrL: {}", commonClientWrapperEntityId, this.ssoUrl);
        HttpHeaders httpHeaders = new HttpHeaders();
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, httpHeaders);
        RestTemplateWrapper restTemplateWrapper = RestTemplateWrapperHelper.getOrCreateRestTemplateWrapperSingleton(commonClientWrapperEntityId);
        ResponseEntity<String> response = restTemplateWrapper.getRestTemplate().postForEntity(this.ssoUrl, request, String.class);
        String responseBody = response.getBody();
        if (StringUtils.contains(responseBody, "Sorry, we could not authenticate you")) {
            throw new ClientIntegrationException("Login/password are not correct");
        }
        return response.getHeaders().getFirst("Location");
    }

    private <T> ResponseEntity<T> executeRedirectRequestAfterSuccessfulAuthorization(String commonClientWrapperEntityId, String url, String initialPath, String signature, HttpHeaders additionalHeaders, Class<T> responseType) throws Exception {
        log.debug("#executeRedirectRequestAfterSuccessfulAuthorization(String commonClientWrapperEntityId, String url, String initialPath, String signature, HttpHeaders additionalHeaders, Class<T> responseType): {}, {}, {}, {}, {}, {}",
                commonClientWrapperEntityId, url, initialPath, signature, additionalHeaders, responseType
        );

        String cookie = String.format("fragmentAfterLogin=; locationAfterLogin=%s; signature=%s", URLEncoder.encode(initialPath, "UTF-8"), signature);
        HttpHeaders headers = new HttpHeaders();
        headers.add("Cookie", cookie);
        if (additionalHeaders != null) {
            headers.addAll(additionalHeaders);
        }

        RequestEntity requestEntity = new RequestEntity(headers, HttpMethod.GET, new URI(url));
        RestTemplateWrapper restTemplateWrapper = RestTemplateWrapperHelper.getOrCreateRestTemplateWrapperSingleton(commonClientWrapperEntityId);
        ResponseEntity<T> responseEntity = restTemplateWrapper.getRestTemplate().exchange(requestEntity, responseType);
        return responseEntity;
    }

    private <T> String getResponseBodyString(ResponseEntity<T> responseEntity) {
        T responseBody = responseEntity.getBody();
        String responseBodyString;
        if (responseBody instanceof String) {
            responseBodyString = (String) responseBody;
        } else if (responseBody instanceof byte[]) {
            responseBodyString = new String((byte[]) responseBody);
        } else {
            throw new ClientIntegrationException(String.format("Can't get string body from %s", responseBody));
        }
        return responseBodyString;
    }

    private String retrieveAuthorizationUrl(String responseBodyString) {
        return getFirstMatchedGroup(responseBodyString, LOCATION_URL_PATTERN, null);
    }

    private String retrieveSignature(String responseBodyString) {
        return getFirstMatchedGroup(responseBodyString, SIGNATURE_PATTERN, "");
    }

    private String retrieveLoginPageUrl(String responseBodyString) {
        return getFirstMatchedGroup(responseBodyString, LOGIN_URL_PATTERN, null);
    }

    private String getFirstMatchedGroup(String responseBodyString, Pattern pattern, String defaultValue) {
        Matcher matcher = pattern.matcher(responseBodyString);
        String foundGroup = defaultValue;
        if (matcher.find()) {
            foundGroup = matcher.group(1);
        }
        return foundGroup;
    }

    private MultiValueMap<String, String> buildLoginFormData(CommonClientWrapperEntity commonClientWrapperEntity, String html) {
        ConnectionProperties connectionProperties = commonClientWrapperEntity.getConnectionProperties();
        Map<String, String> loginFormData = new HashMap<>();
        loginFormData.put("j_username", connectionProperties.getUsername());
        loginFormData.put("j_password", connectionProperties.getPassword());

        Document doc = Jsoup.parse(html);

        Element logOnForm = doc.getElementById("logOnForm");
        Elements inputElements = logOnForm.getElementsByTag("input");

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        for (Element inputElement : inputElements) {
            String ekey = inputElement.attr("name");
            String value = inputElement.attr("value");

            for (String dataKey : loginFormData.keySet()) {
                if (ekey.equals(dataKey))
                    value = loginFormData.get(dataKey);
            }
            map.put(ekey, Collections.singletonList(value));
        }
        return map;
    }
}

