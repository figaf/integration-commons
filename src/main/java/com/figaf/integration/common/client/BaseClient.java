package com.figaf.integration.common.client;

import com.figaf.integration.common.client.support.OAuthTokenInterceptor;
import com.figaf.integration.common.client.support.parser.CloudFoundryOAuthTokenParser;
import com.figaf.integration.common.entity.*;
import com.figaf.integration.common.exception.ClientIntegrationException;
import com.figaf.integration.common.factory.HttpClientsFactory;
import com.figaf.integration.common.factory.RestTemplateWrapperFactory;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
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
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

import java.net.*;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.Collections.singleton;
import static java.util.Collections.singletonList;

/**
 * @author Arsenii Istlentev
 */
@Slf4j
public class BaseClient {

    private final static int MAX_NUMBER_OF_AUTH_ATTEMPTS = 4;
    private final static Pattern LOCATION_URL_PATTERN = Pattern.compile("location=\"(.*)\"<\\/script>");
    private final static Pattern SIGNATURE_PATTERN = Pattern.compile("signature=(.*);path");
    private final static Pattern LOGIN_URL_PATTERN = Pattern.compile("<meta name=\"redirect\"[\\s\\S]*content=\"(.*)\">");
    private final static Pattern PWD_FORM_PATTERN = Pattern.compile("<form id=\"PwdForm\" action=\"([^\"]*)\".*name=\"X-Uaa-Csrf\" value=\"([^\"]*)\"");
    private final static Pattern SAML_REDIRECT_FORM_PATTERN = Pattern.compile("<form id=\"samlRedirect\".*action=\"([^\"]*)\"");
    private final static Pattern SAML_RESPONSE_PATTERN = Pattern.compile("id=\"SAMLResponse\" value=\"([^\"]*)\"");
    private final static Pattern AUTHENTICITY_TOKEN_PATTERN = Pattern.compile("name=\"authenticity_token\".*value=\"([^\"]*)\"");
    private final static Pattern DEFAULT_IDENTITY_PROVIDER_PATTERN = Pattern.compile("<a href=\"(https://accounts\\.sap\\.com/[^\"]*)\"");

    private final static String DEFAULT_SSO_URL = "https://accounts.sap.com/saml2/idp/sso";

    private static final String X_CSRF_TOKEN = "X-CSRF-Token";

    protected final HttpClientsFactory httpClientsFactory;
    protected final RestTemplateWrapperFactory restTemplateWrapperFactory;
    private final RestTemplateWrapperHolder restTemplateWrapperHolder;
    private final CsrfTokenHolder csrfTokenHolder;

    public BaseClient(HttpClientsFactory httpClientsFactory) {
        this.httpClientsFactory = httpClientsFactory;
        this.restTemplateWrapperFactory = new RestTemplateWrapperFactory(httpClientsFactory);
        this.restTemplateWrapperHolder = new RestTemplateWrapperHolder(restTemplateWrapperFactory);
        this.csrfTokenHolder = new CsrfTokenHolder();
    }

    public interface ResponseHandlerCallback<R, T> {
        R apply(T resolvedBody) throws Exception;
    }

    public interface ResponseHandlerCallbackForCrudMethods<R> {
        R apply(String url, String token, RestTemplateWrapper restTemplateWrapper);
    }

    public <R> R executeGet(RequestContext requestContext, String path, ResponseHandlerCallback<R, String> responseHandlerCallback) {
        return executeGet(requestContext, path, responseHandlerCallback, String.class);
    }

    public <R> R executeGetPublicApiAndReturnResponseBody(RequestContext requestContext, String path, ResponseHandlerCallback<R, String> responseHandlerCallback) {
        return executeGetPublicApiAndReturnResponseBody(requestContext, path, null, responseHandlerCallback, String.class);
    }

    public <R> R executeGetPublicApiAndReturnResponseBody(RequestContext requestContext, String path, HttpHeaders httpHeaders, ResponseHandlerCallback<R, String> responseHandlerCallback) {
        return executeGetPublicApiAndReturnResponseBody(requestContext, path, httpHeaders, responseHandlerCallback, String.class);
    }

    public <R> R executeGetPublicApiAndReturnResponseEntity(RequestContext requestContext, String path, ResponseHandlerCallback<R, ResponseEntity<String>> responseHandlerCallback) {
        return executeGetPublicApiAndReturnResponseEntity(requestContext, path, null, responseHandlerCallback, String.class);
    }

    public <R> R executeGetPublicApiAndReturnResponseEntity(RequestContext requestContext, String path, HttpHeaders httpHeaders, ResponseHandlerCallback<R, ResponseEntity<String>> responseHandlerCallback) {
        return executeGetPublicApiAndReturnResponseEntity(requestContext, path, httpHeaders, responseHandlerCallback, String.class);
    }

    public <R, T> R executeGetPublicApiAndReturnResponseBody(RequestContext requestContext, String path, HttpHeaders httpHeaders, ResponseHandlerCallback<R, T> responseHandlerCallback, Class<T> bodyType) {
        ResponseEntity<T> responseEntity = executeGetPublicApi(requestContext, path, httpHeaders, bodyType);
        R response;
        try {
            response = responseHandlerCallback.apply(responseEntity.getBody());
        } catch (Exception ex) {
            log.error("Can't handle response body: ", ex);
            throw new ClientIntegrationException(ex);
        }
        return response;
    }

    public <R, T> R executeGetPublicApiAndReturnResponseEntity(RequestContext requestContext, String path, HttpHeaders httpHeaders, ResponseHandlerCallback<R, ResponseEntity<T>> responseHandlerCallback, Class<T> bodyType) {
        ResponseEntity<T> responseEntity = executeGetPublicApi(requestContext, path, httpHeaders, bodyType);
        R response;
        try {
            response = responseHandlerCallback.apply(responseEntity);
        } catch (Exception ex) {
            log.error("Can't handle response body: ", ex);
            throw new ClientIntegrationException(ex);
        }
        return response;
    }

    public <R, T> R executeGet(RequestContext requestContext, String path, ResponseHandlerCallback<R, T> responseHandlerCallback, Class<T> bodyType) {
        T responseBody;
        if (CloudPlatformType.CLOUD_FOUNDRY.equals(requestContext.getCloudPlatformType())) {
            ResponseEntity<T> initialResponseEntity = executeGetRequestReturningTextBody(requestContext, path, bodyType);
            responseBody = makeAuthRequestsIfNecessaryAndReturnNeededBody(requestContext, path, initialResponseEntity, bodyType);
        } else {
            responseBody = executeGetRequestWithBasicAuthReturningTextBody(requestContext, path, bodyType);
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

    public <R> R executeMethod(RequestContext requestContext, String pathForMainRequest, ResponseHandlerCallbackForCrudMethods<R> responseHandlerCallback) {
        return executeMethod(requestContext, "/itspaces/api/1.0/user", pathForMainRequest, responseHandlerCallback);
    }

    public <R> R executeMethod(RequestContext requestContext, String pathForToken, String pathForMainRequest, ResponseHandlerCallbackForCrudMethods<R> responseHandlerCallback) {
        try {
            if (CloudPlatformType.CLOUD_FOUNDRY.equals(requestContext.getCloudPlatformType())) {
                RestTemplateWrapper restTemplateWrapper = restTemplateWrapperHolder.getOrCreateRestTemplateWrapperSingleton(requestContext.getRestTemplateWrapperKey());
                String token = retrieveToken(requestContext, restTemplateWrapper.getRestTemplate(), pathForToken);
                String url = buildUrl(requestContext, pathForMainRequest);
                return responseHandlerCallback.apply(url, token, restTemplateWrapperHolder.getOrCreateRestTemplateWrapperSingleton(requestContext.getRestTemplateWrapperKey()));
            } else {
                ConnectionProperties connectionProperties = requestContext.getConnectionProperties();
                RestTemplateWrapper restTemplateWrapper = restTemplateWrapperFactory.createRestTemplateWrapper(singleton(
                        new BasicAuthenticationInterceptor(connectionProperties.getUsername(), connectionProperties.getPassword())
                ));
                String token = retrieveToken(requestContext, restTemplateWrapper.getRestTemplate(), pathForToken);
                String url = buildUrl(requestContext, pathForMainRequest);
                return responseHandlerCallback.apply(url, token, restTemplateWrapper);
            }
        } catch (Exception ex) {
            log.error("Can't executeMethod: ", ex);
            throw new ClientIntegrationException(ex);
        }
    }

    public <R> R executeMethodPublicApi(RequestContext requestContext, String pathForMainRequest, String requestBody, HttpMethod httpMethod, ResponseHandlerCallback<R, ResponseEntity<String>> responseHandlerCallback) {
        try {
            RestTemplate restTemplate = getOrCreateRestTemplateWrapperSingletonWithInterceptors(requestContext);

            String tokenUrl = buildUrl(requestContext, "/api/v1");
            String url = buildUrl(requestContext, pathForMainRequest);

            String csrfToken = csrfTokenHolder.getCsrfToken(requestContext.getRestTemplateWrapperKey(), restTemplate, tokenUrl);

            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.setContentType(MediaType.APPLICATION_JSON);
            httpHeaders.add(X_CSRF_TOKEN, csrfToken);

            HttpEntity<String> requestEntity = new HttpEntity<>(requestBody, httpHeaders);

            try {
                ResponseEntity<String> responseEntity = restTemplate.exchange(
                        url,
                        httpMethod,
                        requestEntity,
                        String.class
                );
                return responseHandlerCallback.apply(responseEntity);
            } catch (HttpClientErrorException.Forbidden ex) {
                ResponseEntity<String> responseEntity = processForbiddenHttpClientErrorException(
                        ex,
                        restTemplate,
                        url,
                        tokenUrl,
                        requestEntity,
                        httpMethod,
                        requestContext.getRestTemplateWrapperKey(),
                        requestEntity.getHeaders().getFirst(X_CSRF_TOKEN)
                );
                return responseHandlerCallback.apply(responseEntity);
            }
        } catch (Exception ex) {
            log.error("Can't executeMethodPublicApi: ", ex);
            throw new ClientIntegrationException(ex);
        }
    }


    private String retrieveToken(RequestContext requestContext, RestTemplate restTemplate, String path) {
        try {
            ConnectionProperties connectionProperties = requestContext.getConnectionProperties();
            String url = buildUrl(connectionProperties, path);
            ResponseEntity<String> responseEntity;
            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.add("X-CSRF-Token", "Fetch");
            if (CloudPlatformType.CLOUD_FOUNDRY.equals(requestContext.getCloudPlatformType())) {
                RequestEntity requestEntity = new RequestEntity(httpHeaders, HttpMethod.GET, new URI(url));
                ResponseEntity<String> initialResponseEntity = restTemplate.exchange(requestEntity, String.class);
                if (!HttpStatus.OK.equals(initialResponseEntity.getStatusCode()) || initialResponseEntity.getBody() != null) {
                    responseEntity = makeAuthRequestsIfNecessaryAndReturnResponseEntity(requestContext, path, initialResponseEntity, httpHeaders, String.class, 1);
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

    private String buildUrl(RequestContext requestContext, String path) {
        return buildUrl(requestContext.getConnectionProperties(), path);
    }

    private String buildUrl(ConnectionProperties connectionProperties, String path) {
        return String.format("%s%s", connectionProperties.getUrlRemovingDefaultPortIfNecessary(), path);
    }

    private RestTemplateWrapper getRestTemplateWrapper(RequestContext requestContext) {
        ConnectionProperties connectionProperties = requestContext.getConnectionProperties();
        RestTemplateWrapper restTemplateWrapper;
        if (CloudPlatformType.CLOUD_FOUNDRY.equals(requestContext.getCloudPlatformType())) {
            restTemplateWrapper = restTemplateWrapperHolder.getOrCreateRestTemplateWrapperSingleton(requestContext.getRestTemplateWrapperKey());
        } else {
            restTemplateWrapper = restTemplateWrapperFactory.createRestTemplateWrapper(singleton(
                    new BasicAuthenticationInterceptor(connectionProperties.getUsername(), connectionProperties.getPassword())
            ));
        }
        return restTemplateWrapper;
    }

    private <T> ResponseEntity<T> executeGetRequestReturningTextBody(RequestContext requestContext, String path, Class<T> bodyType) {
        ConnectionProperties connectionProperties = requestContext.getConnectionProperties();
        final String url = buildUrl(connectionProperties, path);
        try {
            RequestEntity requestEntity = new RequestEntity(HttpMethod.GET, new URI(url));
            RestTemplateWrapper restTemplateWrapper = restTemplateWrapperHolder.getOrCreateRestTemplateWrapperSingleton(requestContext.getRestTemplateWrapperKey());
            ResponseEntity<T> responseEntity = restTemplateWrapper.getRestTemplate().exchange(requestEntity, bodyType);
            return responseEntity;
        } catch (Exception ex) {
            String errorMessage = String.format("Can't execute GET request %s successfully: ", url);
            log.error(errorMessage, ex);
            throw new ClientIntegrationException(errorMessage, ex);
        }
    }

    private <T> T executeGetRequestWithBasicAuthReturningTextBody(RequestContext requestContext, String path, Class<T> bodyType) {
        ConnectionProperties connectionProperties = requestContext.getConnectionProperties();
        final String url = buildUrl(connectionProperties, path);
        try {
            RestTemplate restTemplateWithBasicAuth = httpClientsFactory.createRestTemplate(new BasicAuthenticationInterceptor(connectionProperties.getUsername(), connectionProperties.getPassword()));
            RequestEntity requestEntity = new RequestEntity(HttpMethod.GET, new URI(url));
            ResponseEntity<T> responseEntity = restTemplateWithBasicAuth.exchange(requestEntity, bodyType);
            return responseEntity.getBody();
        } catch (Exception ex) {
            String errorMessage = String.format("Can't execute GET request %s successfully: ", url);
            log.error(errorMessage, ex);
            throw new ClientIntegrationException(errorMessage, ex);
        }
    }

    private <T> T makeAuthRequestsIfNecessaryAndReturnNeededBody(RequestContext requestContext, String path, ResponseEntity<T> initialResponseEntity, Class<T> responseType) {
        ResponseEntity<T> responseEntity = makeAuthRequestsIfNecessaryAndReturnResponseEntity(
                requestContext,
                path,
                initialResponseEntity,
                null,
                responseType,
                1
        );
        return responseEntity.getBody();
    }

    private <T> ResponseEntity<T> makeAuthRequestsIfNecessaryAndReturnResponseEntity(
            RequestContext requestContext,
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

            ResponseEntity<T> responseEntity = makeAuthRequests(requestContext, path, additionalHeaders, responseType, responseBodyString, authorizationUrl);

            log.debug("number of attempts = {}", numberOfAttempts);

            return responseEntity;
        } catch (HttpStatusCodeException ex) {
            //sometimes authorization requests fail due to unclear reason. That's why we need to do another attempt.
            if ((HttpStatus.BAD_REQUEST.equals(ex.getStatusCode()) || HttpStatus.INTERNAL_SERVER_ERROR.equals(ex.getStatusCode())) &&
                    numberOfAttempts < MAX_NUMBER_OF_AUTH_ATTEMPTS
            ) {
                log.warn("HttpStatusCodeException occurs: {}, {}", ex.getStatusCode(), ex.getMessage());
                return makeAuthRequestsIfNecessaryAndReturnResponseEntity(requestContext, path, initialResponseEntity, additionalHeaders, responseType, numberOfAttempts + 1);
            } else {
                throw ex;
            }
        } catch (Exception ex) {
            String errorMessage = String.format("Can't authorize and execute initial request on %s", path);
            log.error(errorMessage, ex);
            throw new ClientIntegrationException(errorMessage, ex);
        }
    }

    private <T> ResponseEntity<T> makeAuthRequests(
            RequestContext requestContext,
            String path,
            HttpHeaders additionalHeaders,
            Class<T> responseType,
            String responseBodyString,
            String authorizationUrl
    ) throws Exception {

        //IRT-1891 we need to do this because parallel authorizations cause serious problems
        synchronized (requestContext.getRestTemplateWrapperKey().intern()) {

            String signature = retrieveSignature(responseBodyString);

            String restTemplateWrapperKey = requestContext.getRestTemplateWrapperKey();
            String redirectUrlReceivedAfterSuccessfulAuthorization;

            if (StringUtils.isNotEmpty(requestContext.getLoginPageUrl())) {
                //if we have loginPageUrl, the next call (getAuthorizationPageContent) is needed only for receiving cookies
                getAuthorizationPageContent(restTemplateWrapperKey, authorizationUrl);
                ResponseEntity<String> loginPageContentResponseEntity = getLoginPageContent(restTemplateWrapperKey, requestContext.getLoginPageUrl());
                List<String> cookies = loginPageContentResponseEntity.getHeaders().get(HttpHeaders.SET_COOKIE);
                MultiValueMap<String, String> loginFormData = buildLoginFormDataForSso(requestContext, loginPageContentResponseEntity.getBody());
                redirectUrlReceivedAfterSuccessfulAuthorization = authorize(restTemplateWrapperKey, loginFormData, requestContext.getSsoUrl(), cookies);

                ResponseEntity<T> responseEntity = executeRedirectRequestAfterSuccessfulAuthorization(
                        restTemplateWrapperKey,
                        redirectUrlReceivedAfterSuccessfulAuthorization,
                        path,
                        signature,
                        additionalHeaders,
                        responseType
                );

                String responseBodyAsString = getResponseBodyString(responseEntity);
                String samlRedirectUrl = getFirstMatchedGroup(responseBodyAsString, SAML_REDIRECT_FORM_PATTERN, null);
                //if samlRedirectUrl is null, it means that we already have a result. But if it's not null, we need to do an additional call
                if (samlRedirectUrl == null) {
                    return responseEntity;
                }
                redirectUrlReceivedAfterSuccessfulAuthorization = authorizeViaSaml(restTemplateWrapperKey, responseBodyAsString, samlRedirectUrl);
            } else {

                String authorizationPageContent = getAuthorizationPageContent(restTemplateWrapperKey, authorizationUrl);
                String loginPageUrl = getLoginPageUrlFromAuthorizationPage(authorizationPageContent);
                if (loginPageUrl != null) {
                    ResponseEntity<String> loginPageContentResponseEntity = getLoginPageContent(restTemplateWrapperKey, loginPageUrl);
                    MultiValueMap<String, String> loginFormData = buildLoginFormDataForSso(requestContext, loginPageContentResponseEntity.getBody());
                    redirectUrlReceivedAfterSuccessfulAuthorization = authorize(restTemplateWrapperKey, loginFormData, requestContext.getSsoUrl(), null);
                } else {
                    Matcher matcher = PWD_FORM_PATTERN.matcher(authorizationPageContent);
                    String loginDoPath;
                    String csrfToken;
                    if (matcher.find()) {
                        loginDoPath = matcher.group(1);
                        csrfToken = matcher.group(2);
                    } else {
                        throw new ClientIntegrationException(String.format("Can't retrieve login page url or login form data from %s", authorizationPageContent));
                    }

                    MultiValueMap<String, String> loginFormData = buildLoginFormData(requestContext, csrfToken);
                    String loginUrl = buildLoginUrl(authorizationUrl, loginDoPath);
                    redirectUrlReceivedAfterSuccessfulAuthorization = authorize(restTemplateWrapperKey, loginFormData, loginUrl, null);
                }
            }

            return executeRedirectRequestAfterSuccessfulAuthorization(
                    restTemplateWrapperKey,
                    redirectUrlReceivedAfterSuccessfulAuthorization,
                    path,
                    signature,
                    additionalHeaders,
                    responseType
            );

        }
    }

    private String getAuthorizationPageContent(String restTemplateWrapperKey, String url) throws URISyntaxException {
        log.debug("#getAuthorizationPageContent(String restTemplateWrapperKey, String url): {}, {}", restTemplateWrapperKey, url);
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9");
        RequestEntity requestEntity = new RequestEntity(httpHeaders, HttpMethod.GET, new URI(url));

        RestTemplateWrapper restTemplateWrapper = restTemplateWrapperHolder.getOrCreateRestTemplateWrapperSingleton(restTemplateWrapperKey);
        ResponseEntity<String> responseEntity;
        try {
            responseEntity = restTemplateWrapper.getRestTemplate().exchange(requestEntity, String.class);
        } catch (HttpStatusCodeException ex) {
            if (HttpStatus.BAD_REQUEST.equals(ex.getStatusCode())) {
                restTemplateWrapper = restTemplateWrapperHolder.createNewRestTemplateWrapper(restTemplateWrapperKey);
                responseEntity = restTemplateWrapper.getRestTemplate().exchange(requestEntity, String.class);
            } else {
                throw ex;
            }
        }

        return responseEntity.getBody();
    }

    private String getLoginPageUrlFromAuthorizationPage(String authorizationPageContent) {
        log.debug("#getLoginPageUrlFromAuthorizationPage(String authorizationPageContent)");
        String loginPageUrl = retrieveLoginPageUrl(authorizationPageContent);
        return loginPageUrl != null ? loginPageUrl.replaceAll("amp;", "") : null;
    }

    private ResponseEntity<String> getLoginPageContent(String restTemplateWrapperKey, String url) throws Exception {
        log.debug("#getLoginPageContent(String restTemplateWrapperKey, String url): {}, {}", restTemplateWrapperKey, url);
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Accept", "*/*");
        RequestEntity requestEntity = new RequestEntity(httpHeaders, HttpMethod.GET, new URI(url));
        RestTemplateWrapper restTemplateWrapper = restTemplateWrapperHolder.getOrCreateRestTemplateWrapperSingleton(restTemplateWrapperKey);
        ResponseEntity<String> exchange = restTemplateWrapper.getRestTemplate().exchange(requestEntity, String.class);
        return exchange;
    }

    private String authorize(String restTemplateWrapperKey, MultiValueMap<String, String> map, String loginUrl, List<String> cookies) {
        log.debug("#authorize(String restTemplateWrapperKey, MultiValueMap<String, String> map, String loginUrl): {}, {}", restTemplateWrapperKey, loginUrl);
        if (StringUtils.isEmpty(loginUrl)) {
            loginUrl = DEFAULT_SSO_URL;
        }
        HttpHeaders httpHeaders = new HttpHeaders();
        if (CollectionUtils.isNotEmpty(cookies)) {
            httpHeaders.add("Cookie", StringUtils.join(cookies, "; "));
        }
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, httpHeaders);
        RestTemplateWrapper restTemplateWrapper = restTemplateWrapperHolder.getOrCreateRestTemplateWrapperSingleton(restTemplateWrapperKey);
        ResponseEntity<String> response = restTemplateWrapper.getRestTemplate().postForEntity(loginUrl, request, String.class);
        String responseBody = response.getBody();
        if (StringUtils.contains(responseBody, "Sorry, we could not authenticate you")) {
            throw new ClientIntegrationException("Login/password are not correct");
        }
        return response.getHeaders().getFirst("Location");
    }

    private String authorizeViaSaml(String restTemplateWrapperKey, String responseBodyAsString, String samlRedirectUrl) {
        String redirectUrlReceivedAfterSuccessfulAuthorization;
        String samlResponse = getFirstMatchedGroup(responseBodyAsString, SAML_RESPONSE_PATTERN, null);
        String authenticityToken = getFirstMatchedGroup(responseBodyAsString, AUTHENTICITY_TOKEN_PATTERN, null);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("authenticity_token", authenticityToken);
        body.add("SAMLResponse", samlResponse);
        HttpHeaders httpHeaders = new HttpHeaders();
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, httpHeaders);
        RestTemplateWrapper restTemplateWrapper = restTemplateWrapperHolder.getOrCreateRestTemplateWrapperSingleton(restTemplateWrapperKey);
        ResponseEntity<String> responseEntity = restTemplateWrapper.getRestTemplate().postForEntity(samlRedirectUrl, request, String.class);
        redirectUrlReceivedAfterSuccessfulAuthorization = responseEntity.getHeaders().getFirst("location");
        return redirectUrlReceivedAfterSuccessfulAuthorization;
    }

    private <T> ResponseEntity<T> executeRedirectRequestAfterSuccessfulAuthorization(String restTemplateWrapperKey, String url, String initialPath, String signature, HttpHeaders additionalHeaders, Class<T> responseType) throws Exception {
        log.debug("#executeRedirectRequestAfterSuccessfulAuthorization(String restTemplateWrapperKey, String url, String initialPath, String signature, HttpHeaders additionalHeaders, Class<T> responseType): {}, {}, {}, {}, {}, {}",
                restTemplateWrapperKey, url, initialPath, signature, additionalHeaders, responseType
        );

        String cookie = String.format("fragmentAfterLogin=; locationAfterLogin=%s; signature=%s", URLEncoder.encode(initialPath, "UTF-8"), signature);
        HttpHeaders headers = new HttpHeaders();
        headers.add("Cookie", cookie);
        if (additionalHeaders != null) {
            headers.addAll(additionalHeaders);
        }

        RequestEntity requestEntity = new RequestEntity(headers, HttpMethod.GET, new URI(url));
        RestTemplateWrapper restTemplateWrapper = restTemplateWrapperHolder.getOrCreateRestTemplateWrapperSingleton(restTemplateWrapperKey);

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
        String loginPageUrl = getFirstMatchedGroup(responseBodyString, LOGIN_URL_PATTERN, null);
        if (loginPageUrl == null) {
            loginPageUrl = getFirstMatchedGroup(responseBodyString, DEFAULT_IDENTITY_PROVIDER_PATTERN, null);
        }
        return loginPageUrl;
    }

    private String getFirstMatchedGroup(String responseBodyString, Pattern pattern, String defaultValue) {
        Matcher matcher = pattern.matcher(responseBodyString);
        String foundGroup = defaultValue;
        if (matcher.find()) {
            foundGroup = matcher.group(1);
        }
        return foundGroup;
    }

    private MultiValueMap<String, String> buildLoginFormDataForSso(RequestContext requestContext, String html) {
        ConnectionProperties connectionProperties = requestContext.getConnectionProperties();
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

    private MultiValueMap<String, String> buildLoginFormData(RequestContext requestContext, String csrfToken) {
        ConnectionProperties connectionProperties = requestContext.getConnectionProperties();
        MultiValueMap<String, String> loginFormData = new LinkedMultiValueMap<>();
        loginFormData.add("username", connectionProperties.getUsername());
        loginFormData.add("password", connectionProperties.getPassword());
        loginFormData.add("X-Uaa-Csrf", csrfToken);
        return loginFormData;
    }

    private String buildLoginUrl(String authorizationUrl, String loginDoPath) throws MalformedURLException {
        URL url = new URL(authorizationUrl);
        return String.format("%s://%s/%s", url.getProtocol(), url.getAuthority(), loginDoPath);
    }

    private <T> ResponseEntity<T> executeGetPublicApi(RequestContext requestContext, String path, HttpHeaders httpHeaders, Class<T> bodyType) {
        RestTemplate restTemplate = getOrCreateRestTemplateWrapperSingletonWithInterceptors(requestContext);

        String url = buildUrl(requestContext, path);

        if (httpHeaders == null) {
            httpHeaders = new HttpHeaders();
        }
        if (httpHeaders.getContentType() == null) {
            httpHeaders.setContentType(MediaType.APPLICATION_JSON);
        }
        HttpEntity<Map<String, String>> requestEntity = new HttpEntity<>(httpHeaders);
        return restTemplate.exchange(
                url,
                HttpMethod.GET,
                requestEntity,
                bodyType
        );
    }

    public RestTemplate getOrCreateRestTemplateWrapperSingletonWithInterceptors(RequestContext requestContext) {
        RestTemplate restTemplate;
        if (CloudPlatformType.CLOUD_FOUNDRY.equals(requestContext.getCloudPlatformType()) && AuthenticationType.OAUTH.equals(requestContext.getAuthenticationType())) {
            restTemplate = restTemplateWrapperHolder.getOrCreateRestTemplateWrapperSingletonWithInterceptors(
                    requestContext.getRestTemplateWrapperKey(),
                    singleton(new OAuthTokenInterceptor(
                            new OAuthTokenRequestContext(
                                    requestContext.getClientId(),
                                    requestContext.getClientSecret(),
                                    requestContext.getOauthUrl()
                            ),
                            new CloudFoundryOAuthTokenParser(),
                            httpClientsFactory
                    ))
            ).getRestTemplate();
        } else {
            restTemplate = restTemplateWrapperHolder.getOrCreateRestTemplateWrapperSingletonWithInterceptors(
                    requestContext.getRestTemplateWrapperKey(),
                    singleton(
                            new BasicAuthenticationInterceptor(requestContext.getConnectionProperties().getUsername(), requestContext.getConnectionProperties().getPassword())
                    )
            ).getRestTemplate();
        }
        return restTemplate;
    }

    private ResponseEntity<String> processForbiddenHttpClientErrorException(
            HttpClientErrorException.Forbidden ex,
            RestTemplate restTemplate,
            String url,
            String tokenUrl,
            HttpEntity<String> requestEntity,
            HttpMethod httpMethod,
            String key,
            String oldToken
    ) {
        if (ex.getResponseHeaders() != null &&
                "required".equalsIgnoreCase(ex.getResponseHeaders().getFirst(X_CSRF_TOKEN))
        ) {
            log.warn("xsrf token will be updated");
            return restTemplate.exchange(
                    url,
                    httpMethod,
                    createRequestEntityWithNewCsrfToken(
                            restTemplate,
                            tokenUrl,
                            requestEntity,
                            key,
                            oldToken
                    ),
                    String.class
            );
        } else {
            throw ex;
        }
    }

    private HttpEntity<String> createRequestEntityWithNewCsrfToken(
            RestTemplate restTemplate,
            String url,
            HttpEntity<String> requestEntity,
            String tokenKey,
            String oldToken
    ) {
        String csrfToken = csrfTokenHolder.getAndSaveNewCsrfTokenIfNeed(tokenKey, restTemplate, url, oldToken);
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.addAll(requestEntity.getHeaders());
        httpHeaders.put(X_CSRF_TOKEN, singletonList(csrfToken));
        return new HttpEntity<>(requestEntity.getBody(), httpHeaders);
    }

}

