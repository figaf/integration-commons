package com.figaf.integration.common.client;

import com.figaf.integration.common.client.support.OAuthTokenInterceptor;
import com.figaf.integration.common.client.support.parser.CloudFoundryOAuthTokenParser;
import com.figaf.integration.common.client.support.parser.SamlRequestParser;
import com.figaf.integration.common.entity.*;
import com.figaf.integration.common.exception.ClientIntegrationException;
import com.figaf.integration.common.factory.HttpClientsFactory;
import com.figaf.integration.common.factory.RestTemplateWrapperFactory;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
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
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.lang.String.format;
import static java.util.Collections.singleton;
import static java.util.Collections.singletonList;
import static org.springframework.http.HttpMethod.DELETE;

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

    private static final ConcurrentMap<String, LockStatus> LOCK_STATUSES = new ConcurrentHashMap<>();

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

    public interface ResponseHandlerCallback<RESULT, RESP> {
        RESULT apply(RESP resolvedBody) throws Exception;
    }

    public interface ResponseHandlerCallbackForCrudMethods<RESULT> {
        RESULT apply(String url, String token, RestTemplateWrapper restTemplateWrapper);
    }

    public <RESULT> RESULT executeGet(
        RequestContext requestContext,
        String path,
        ResponseHandlerCallback<RESULT, String> responseHandlerCallback
    ) {
        return executeGet(requestContext, path, responseHandlerCallback, String.class);
    }

    public <RESULT> RESULT executeGetPublicApiAndReturnResponseBody(
        RequestContext requestContext,
        String path,
        ResponseHandlerCallback<RESULT, String> responseHandlerCallback
    ) {
        return executeGetPublicApiAndReturnResponseBody(requestContext, path, null, responseHandlerCallback, String.class);
    }

    public <RESULT> RESULT executeGetPublicApiAndReturnResponseBody(
        RequestContext requestContext,
        String path,
        HttpHeaders httpHeaders,
        ResponseHandlerCallback<RESULT, String> responseHandlerCallback
    ) {
        return executeGetPublicApiAndReturnResponseBody(requestContext, path, httpHeaders, responseHandlerCallback, String.class);
    }

    public <RESULT> RESULT executeGetPublicApiAndReturnResponseEntity(
        RequestContext requestContext,
        String path,
        ResponseHandlerCallback<RESULT, ResponseEntity<String>> responseHandlerCallback) {
        return executeGetPublicApiAndReturnResponseEntity(requestContext, path, null, responseHandlerCallback, String.class);
    }

    public <RESULT> RESULT executeGetPublicApiAndReturnResponseEntity(
        RequestContext requestContext,
        String path,
        HttpHeaders httpHeaders,
        ResponseHandlerCallback<RESULT, ResponseEntity<String>> responseHandlerCallback
    ) {
        return executeGetPublicApiAndReturnResponseEntity(requestContext, path, httpHeaders, responseHandlerCallback, String.class);
    }

    public <RESULT, RESP> RESULT executeGetPublicApiAndReturnResponseBody(
        RequestContext requestContext,
        String path,
        HttpHeaders httpHeaders,
        ResponseHandlerCallback<RESULT, RESP> responseHandlerCallback,
        Class<RESP> bodyType
    ) {
        ResponseEntity<RESP> responseEntity = executeGetPublicApi(requestContext, path, httpHeaders, bodyType);
        RESULT response;
        try {
            response = responseHandlerCallback.apply(responseEntity.getBody());
        } catch (ClientIntegrationException ex) {
            throw ex;
        } catch (Exception ex) {
            log.error("Can't handle response body: ", ex);
            throw new ClientIntegrationException(ex);
        }
        return response;
    }

    public <RESULT, RESP> RESULT executeGetPublicApiAndReturnResponseEntity(
        RequestContext requestContext,
        String path,
        HttpHeaders httpHeaders,
        ResponseHandlerCallback<RESULT, ResponseEntity<RESP>> responseHandlerCallback,
        Class<RESP> bodyType
    ) {
        ResponseEntity<RESP> responseEntity = executeGetPublicApi(requestContext, path, httpHeaders, bodyType);
        RESULT response;
        try {
            response = responseHandlerCallback.apply(responseEntity);
        } catch (ClientIntegrationException ex) {
            throw ex;
        } catch (Exception ex) {
            log.error("Can't handle response body: ", ex);
            throw new ClientIntegrationException(ex);
        }
        return response;
    }

    public <RESULT, RESPONSE> RESULT executeGet(
        RequestContext requestContext,
        String path,
        ResponseHandlerCallback<RESULT, RESPONSE> responseHandlerCallback,
        Class<RESPONSE> bodyType
    ) {
        RESPONSE responseBody;
        if (CloudPlatformType.CLOUD_FOUNDRY.equals(requestContext.getCloudPlatformType())) {
            ResponseEntity<RESPONSE> initialResponseEntity = executeGetRequestReturningTextBody(
                requestContext,
                null,
                path,
                bodyType
            );
            responseBody = makeAuthRequestsIfNecessaryAndReturnNeededBody(
                requestContext,
                null,
                path,
                initialResponseEntity,
                bodyType
            );
        } else {
            responseBody = executeGetRequestWithBasicAuthReturningTextBody(
                requestContext,
                path,
                null,
                bodyType
            );
        }

        return processResponse(
            requestContext,
            responseHandlerCallback,
            responseBody
        );
    }

    public <RESULT, RESPONSE> RESULT executeGet(
        RequestContext requestContext,
        HttpHeaders additionalHeaders,
        String path,
        ResponseHandlerCallback<RESULT, RESPONSE> responseHandlerCallback,
        Class<RESPONSE> bodyType
    ) {
        RESPONSE responseBody;
        if (CloudPlatformType.CLOUD_FOUNDRY.equals(requestContext.getCloudPlatformType())) {
            ResponseEntity<RESPONSE> initialResponseEntity = executeGetRequestReturningTextBody(
                requestContext,
                additionalHeaders,
                path,
                bodyType
            );
            responseBody = makeAuthRequestsIfNecessaryAndReturnNeededBody(
                requestContext,
                additionalHeaders,
                path,
                initialResponseEntity,
                bodyType
            );
        } else {
            responseBody = executeGetRequestWithBasicAuthReturningTextBody(
                requestContext,
                path,
                additionalHeaders,
                bodyType
            );
        }

        return processResponse(
            requestContext,
            responseHandlerCallback,
            responseBody
        );
    }

    public <RESULT> RESULT executeMethod(
        RequestContext requestContext,
        String pathForMainRequest,
        ResponseHandlerCallbackForCrudMethods<RESULT> responseHandlerCallback
    ) {
        return executeMethod(requestContext, "/itspaces/api/1.0/user", pathForMainRequest, responseHandlerCallback);
    }

    public <RESULT> RESULT executeMethod(
        RequestContext requestContext,
        String pathForToken,
        String pathForMainRequest,
        ResponseHandlerCallbackForCrudMethods<RESULT> responseHandlerCallback
    ) {
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
        } catch (ClientIntegrationException ex) {
            throwSpecificExceptionIfSsoUrlIsWrong(requestContext, ex);
            throw ex;
        } catch (Exception ex) {
            log.error("Can't executeMethod: ", ex);
            throwSpecificExceptionIfSsoUrlIsWrong(requestContext, ex);
            throw new ClientIntegrationException(ex);
        }
    }

    public <RESULT, REQ> RESULT executeMethodPublicApi(
        RequestContext requestContext,
        String pathForMainRequest,
        REQ requestBody,
        HttpMethod httpMethod,
        ResponseHandlerCallback<RESULT, ResponseEntity<String>> responseHandlerCallback
    ) {
        try {
            RestTemplate restTemplate = getOrCreateRestTemplateWrapperSingletonWithInterceptors(requestContext);
            String tokenUrl = buildUrl(requestContext, "/api/v1");
            String url = buildUrl(requestContext, pathForMainRequest);
            HttpHeaders httpHeaders = createHttpHeadersForPublicApiMethods(requestContext, restTemplate, tokenUrl);
            HttpEntity<REQ> requestEntity = new HttpEntity<>(requestBody, httpHeaders);
            return executeMethodPublicApi(
                requestContext,
                restTemplate,
                url,
                tokenUrl,
                httpMethod,
                requestEntity,
                responseHandlerCallback,
                String.class
            );
        } catch (ClientIntegrationException ex) {
            throw ex;
        } catch (Exception ex) {
            log.error("Can't executeMethodPublicApi: ", ex);
            throw new ClientIntegrationException(ex);
        }
    }

    public <RESULT, REQ> RESULT executeMethodPublicApiWithCustomHeaders(
        RequestContext requestContext,
        String pathForMainRequest,
        REQ requestBody,
        HttpMethod httpMethod,
        HttpHeaders httpHeaders,
        ResponseHandlerCallback<RESULT, ResponseEntity<String>> responseHandlerCallback
    ) {
        try {
            RestTemplate restTemplate = getOrCreateRestTemplateWrapperSingletonWithInterceptors(requestContext);
            String tokenUrl = buildUrl(requestContext, "/api/v1");
            String url = buildUrl(requestContext, pathForMainRequest);
            HttpEntity<REQ> requestEntity = new HttpEntity<>(requestBody, httpHeaders);
            return executeMethodPublicApi(
                requestContext,
                restTemplate,
                url,
                tokenUrl,
                httpMethod,
                requestEntity,
                responseHandlerCallback,
                String.class
            );
        } catch (ClientIntegrationException ex) {
            throw ex;
        } catch (Exception ex) {
            log.error("Can't executeMethodPublicApi: ", ex);
            throw new ClientIntegrationException(ex);
        }
    }

    public <RESULT, REQ> RESULT executeMethodPublicApiAppendingCustomHeaders(
        RequestContext requestContext,
        String pathForMainRequest,
        REQ requestBody,
        HttpMethod httpMethod,
        HttpHeaders customHttpHeaders,
        ResponseHandlerCallback<RESULT, ResponseEntity<String>> responseHandlerCallback
    ) {
        try {
            RestTemplate restTemplate = getOrCreateRestTemplateWrapperSingletonWithInterceptors(requestContext);
            String tokenUrl = buildUrl(requestContext, "/api/v1");
            HttpHeaders httpHeaders = createHttpHeadersForPublicApiMethods(requestContext, restTemplate, tokenUrl);
            httpHeaders.addAll(customHttpHeaders);
            return executeMethodPublicApiWithCustomHeaders(
                requestContext,
                pathForMainRequest,
                requestBody,
                httpMethod,
                httpHeaders,
                responseHandlerCallback
            );
        } catch (ClientIntegrationException ex) {
            throw ex;
        } catch (Exception ex) {
            log.error("Can't executeMethodPublicApiAppendingCustomHeaders: ", ex);
            throw new ClientIntegrationException(ex);
        }
    }

    public <RESULT, RESP> RESULT executeMethodPublicApi(
        RequestContext requestContext,
        String pathForMainRequest,
        String requestBody,
        HttpMethod httpMethod,
        ResponseHandlerCallback<RESULT, ResponseEntity<RESP>> responseHandlerCallback,
        Class<RESP> bodyType
    ) {
        try {
            RestTemplate restTemplate = getOrCreateRestTemplateWrapperSingletonWithInterceptors(requestContext);
            String tokenUrl = buildUrl(requestContext, "/api/v1");
            String url = buildUrl(requestContext, pathForMainRequest);
            HttpHeaders httpHeaders = createHttpHeadersForPublicApiMethods(requestContext, restTemplate, tokenUrl);
            HttpEntity<String> requestEntity = new HttpEntity<>(requestBody, httpHeaders);
            return executeMethodPublicApi(
                requestContext,
                restTemplate,
                url,
                tokenUrl,
                httpMethod,
                requestEntity,
                responseHandlerCallback,
                bodyType
            );
        } catch (ClientIntegrationException ex) {
            throw ex;
        } catch (Exception ex) {
            log.error("Can't executeMethodPublicApi: ", ex);
            throw new ClientIntegrationException(ex);
        }
    }

    public <RESULT> RESULT executeDeletePublicApi(
        RequestContext requestContext,
        String pathForMainRequest,
        ResponseHandlerCallback<RESULT, ResponseEntity<String>> responseHandlerCallback
    ) {
        try {
            RestTemplate restTemplate = getOrCreateRestTemplateWrapperSingletonWithInterceptors(requestContext);
            String url = buildUrl(requestContext, pathForMainRequest);
            String tokenUrl = buildUrl(requestContext, "/api/v1");
            HttpHeaders httpHeaders = createHttpHeadersForPublicApiMethods(requestContext, restTemplate, tokenUrl);
            HttpEntity<Void> requestEntity = new HttpEntity<>(httpHeaders);
            return executeMethodPublicApi(
                requestContext,
                restTemplate,
                url,
                tokenUrl,
                DELETE,
                requestEntity,
                responseHandlerCallback,
                String.class
            );
        } catch (HttpClientErrorException.NotFound notFoundException) {
            log.debug("Can't executeDeletePublicApi (NotFound error): {}", ExceptionUtils.getMessage(notFoundException));
            try {
                return responseHandlerCallback.apply(null);
            } catch (ClientIntegrationException ex) {
                throw ex;
            } catch (Exception ex) {
                log.error("Can't apply responseHandlerCallback: ", ex);
                throw new ClientIntegrationException(ex);
            }
        } catch (ClientIntegrationException ex) {
            throw ex;
        } catch (Exception ex) {
            log.error("Can't executeDeletePublicApi: ", ex);
            throw new ClientIntegrationException(ex);
        }
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

    protected HttpHeaders createHttpHeadersWithCSRFToken(String token) {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(X_CSRF_TOKEN, token);
        return httpHeaders;
    }

    private <RESULT, REQ, RESP> RESULT executeMethodPublicApi(
        RequestContext requestContext,
        RestTemplate restTemplate,
        String url,
        String tokenUrl,
        HttpMethod httpMethod,
        HttpEntity<REQ> requestEntity,
        ResponseHandlerCallback<RESULT, ResponseEntity<RESP>> responseHandlerCallback,
        Class<RESP> bodyType
    ) throws Exception {
        try {
            ResponseEntity<RESP> responseEntity = restTemplate.exchange(
                url,
                httpMethod,
                requestEntity,
                bodyType
            );
            return responseHandlerCallback.apply(responseEntity);
        } catch (HttpClientErrorException.Forbidden ex) {
            ResponseEntity<RESP> responseEntity = processForbiddenHttpClientErrorException(
                ex,
                restTemplate,
                url,
                tokenUrl,
                requestEntity,
                httpMethod,
                requestContext.getRestTemplateWrapperKey(),
                requestEntity.getHeaders().getFirst(X_CSRF_TOKEN),
                bodyType
            );
            return responseHandlerCallback.apply(responseEntity);
        }
    }

    private HttpHeaders createHttpHeadersForPublicApiMethods(
        RequestContext requestContext,
        RestTemplate restTemplate,
        String tokenUrl
    ) {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setContentType(MediaType.APPLICATION_JSON);
        if (requestContext.getPlatform().equals(Platform.API_MANAGEMENT) &&
            requestContext.getAuthenticationType().equals(AuthenticationType.OAUTH)) {
            return httpHeaders;
        }
        String csrfToken = csrfTokenHolder.getCsrfToken(requestContext.getRestTemplateWrapperKey(), restTemplate, tokenUrl);
        httpHeaders.add(X_CSRF_TOKEN, csrfToken);
        return httpHeaders;
    }

    private String retrieveToken(RequestContext requestContext, RestTemplate restTemplate, String path) {
        try {
            ConnectionProperties connectionProperties = requestContext.getConnectionProperties();
            String url = buildUrl(connectionProperties, path);
            ResponseEntity<String> responseEntity;
            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.add(X_CSRF_TOKEN, "Fetch");
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

            String token = responseEntity.getHeaders().getFirst(X_CSRF_TOKEN);
            return token;
        } catch (ClientIntegrationException ex) {
            throw ex;
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

    private <RESULT> ResponseEntity<RESULT> executeGetRequestReturningTextBody(
        RequestContext requestContext,
        HttpHeaders httpHeaders,
        String path,
        Class<RESULT> bodyType
    ) {
        ConnectionProperties connectionProperties = requestContext.getConnectionProperties();
        final String url = buildUrl(connectionProperties, path);
        RequestEntity requestEntity;
        try {
            if (httpHeaders == null) {
                requestEntity = new RequestEntity(HttpMethod.GET, new URI(url));
            } else {
                requestEntity = new RequestEntity(httpHeaders, HttpMethod.GET, new URI(url));
            }
            RestTemplateWrapper restTemplateWrapper = restTemplateWrapperHolder.getOrCreateRestTemplateWrapperSingleton(requestContext.getRestTemplateWrapperKey());
            ResponseEntity<RESULT> responseEntity = restTemplateWrapper.getRestTemplate().exchange(requestEntity, bodyType);
            return responseEntity;
        } catch (ClientIntegrationException ex) {
            throw ex;
        } catch (Exception ex) {
            String errorMessage = String.format("Can't execute GET request %s successfully: ", url);
            log.error(errorMessage, ex);
            throw new ClientIntegrationException(errorMessage, ex);
        }
    }

    private <RESULT> RESULT executeGetRequestWithBasicAuthReturningTextBody(
        RequestContext requestContext,
        String path,
        HttpHeaders httpHeaders,
        Class<RESULT> bodyType
    ) {
        ConnectionProperties connectionProperties = requestContext.getConnectionProperties();
        final String url = buildUrl(connectionProperties, path);
        try {
            RestTemplate restTemplateWithBasicAuth = httpClientsFactory.createRestTemplate(new BasicAuthenticationInterceptor(connectionProperties.getUsername(), connectionProperties.getPassword()));
            RequestEntity requestEntity;
            if (httpHeaders == null) {
                requestEntity = new RequestEntity(HttpMethod.GET, new URI(url));
            } else {
                requestEntity = new RequestEntity(httpHeaders, HttpMethod.GET, new URI(url));
            }
            ResponseEntity<RESULT> responseEntity = restTemplateWithBasicAuth.exchange(requestEntity, bodyType);
            return responseEntity.getBody();
        } catch (ClientIntegrationException ex) {
            throw ex;
        } catch (Exception ex) {
            String errorMessage = String.format("Can't execute GET request %s successfully: ", url);
            log.error(errorMessage, ex);
            throw new ClientIntegrationException(errorMessage, ex);
        }
    }

    private <RESULT> RESULT makeAuthRequestsIfNecessaryAndReturnNeededBody(
        RequestContext requestContext,
        HttpHeaders additionalHeaders,
        String path,
        ResponseEntity<RESULT> initialResponseEntity,
        Class<RESULT> responseType
    ) {
        ResponseEntity<RESULT> responseEntity = makeAuthRequestsIfNecessaryAndReturnResponseEntity(
            requestContext,
            path,
            initialResponseEntity,
            additionalHeaders,
            responseType,
            1
        );
        return responseEntity.getBody();
    }

    private <RESULT> ResponseEntity<RESULT> makeAuthRequestsIfNecessaryAndReturnResponseEntity(
        RequestContext requestContext,
        String path,
        ResponseEntity<RESULT> initialResponseEntity,
        HttpHeaders additionalHeaders,
        Class<RESULT> responseType,
        int numberOfAttempts
    ) {
        try {
            String responseBodyString = getResponseBodyString(initialResponseEntity);

            String authorizationUrl = retrieveAuthorizationUrl(responseBodyString);
            if (authorizationUrl == null) {
                return initialResponseEntity;
            }

            ResponseEntity<RESULT> responseEntity = makeAuthRequestsWithLock(
                requestContext,
                path,
                additionalHeaders,
                responseType,
                responseBodyString,
                authorizationUrl
            );

            log.debug("number of attempts = {}", numberOfAttempts);

            return responseEntity;
        } catch (HttpStatusCodeException ex) {
            //sometimes authorization requests fail due to unclear reason. That's why we need to do another attempt.
            if ((HttpStatus.BAD_REQUEST.equals(ex.getStatusCode()) || HttpStatus.INTERNAL_SERVER_ERROR.equals(ex.getStatusCode())) &&
                numberOfAttempts < MAX_NUMBER_OF_AUTH_ATTEMPTS
            ) {
                log.warn("HttpStatusCodeException occurs: {}, {}", ex.getStatusCode(), ex.getMessage());
                return makeAuthRequestsIfNecessaryAndReturnResponseEntity(
                    requestContext,
                    path,
                    initialResponseEntity,
                    additionalHeaders,
                    responseType,
                    numberOfAttempts + 1
                );
            } else {
                throw ex;
            }
        } catch (ClientIntegrationException ex) {
            throw ex;
        } catch (Exception ex) {
            String errorMessage = String.format("Can't authorize and execute initial request on %s", path);
            log.error(errorMessage, ex);
            throw new ClientIntegrationException(errorMessage, ex);
        }
    }

    private <RESULT> ResponseEntity<RESULT> makeAuthRequestsWithLock(
        RequestContext requestContext,
        String path,
        HttpHeaders additionalHeaders,
        Class<RESULT> responseType,
        String responseBodyString,
        String authorizationUrl
    ) throws Exception {
        /*IRT-1891, IRT-4038: we need to do this because parallel authorizations cause serious problems

        We need to avoid processing parallel authentication attempts for the same session context (based on restTemplateWrapperKey)
        But it's not enough. In IRT-4038, in case of IS agent without custom idp (probably it's reproducible for custom idp as well)
        we faced an issue when sequential (due to the synchronized block) authentication attempts were not idempotent. For example:

        Let's we have 3 concurrent requests to fetch Integration Packages and no session
        for current restTemplateWrapperKey at the moment, i.e all 3 GET requests are executed at the same time and failed due to the lack of the session.
        After that related threads execute authentication logic, it has synchronized block, so, they will be processed sequentially
        in that synchronized block. But only the first request processed all steps that are required for successful flow.
        Remaining requests for some reason didn't follow same flow and almost immediately failed with 404 error when processing
        GET /login/callback?code=...

        Anyway it's useless to process the full auth again when it has just been processed. So, it's expected to have the following behavior:

        When we have multiple threads locked by the same restTemplateWrapperKey in that method, only the first one should process authentication e2e,
        other should try to process the main query again.
         */
        LockStatus lockStatus = LOCK_STATUSES.computeIfAbsent(requestContext.getRestTemplateWrapperKey(), k -> new LockStatus());
        lockStatus.getWaitingThreadCount().incrementAndGet(); // Increment waiting thread count
        lockStatus.getLock().lock();
        try {
            if (lockStatus.isAuthProcessed()) {
                log.debug("skipping authentication, trying to execute the main query");
                return executeGetRequestReturningTextBody(requestContext, null, path, responseType);
            }

            ResponseEntity<RESULT> responseEntity = makeAuthRequests(
                requestContext,
                path,
                additionalHeaders,
                responseType,
                responseBodyString,
                authorizationUrl
            );

            lockStatus.setAuthProcessed(true); // Mark the auth block as processed
            return responseEntity;
        } finally {
            lockStatus.getWaitingThreadCount().decrementAndGet(); // Decrement waiting thread count
            if (lockStatus.getWaitingThreadCount().get() == 0) {
                lockStatus.setAuthProcessed(false);
            }
            lockStatus.getLock().unlock(); // Ensure the lock is released
        }
    }

    private <RESULT> ResponseEntity<RESULT> makeAuthRequests(
        RequestContext requestContext,
        String path,
        HttpHeaders additionalHeaders,
        Class<RESULT> responseType,
        String responseBodyString,
        String authorizationUrl
    ) throws Exception {
        log.debug("processing authentication");
        String signature = retrieveSignature(responseBodyString);

        String restTemplateWrapperKey = requestContext.getRestTemplateWrapperKey();
        String redirectUrlReceivedAfterSuccessfulAuthorization;

        if (requestContext.isUseCustomIdp()) {
            //Not the best way to check that Entity Descriptor was generated and uploaded. Basically, SAML Url is not needed anymore for authentication from IRT deployment (it's still needed for the gradle plugins), but it defines if Entity Descriptor generation was done.
            if (StringUtils.isEmpty(requestContext.getSamlUrl())) {
                throw new ClientIntegrationException("SAML Url is empty. Please generate an Entity Descriptor in the Figaf tool and upload a new Trust Configuration in your SAP cockpit");
            }
            authorizeViaCustomIdpProvider(requestContext, authorizationUrl);
            redirectUrlReceivedAfterSuccessfulAuthorization = authorizationUrl;
        } else if (StringUtils.isNotEmpty(requestContext.getLoginPageUrl())) {
            //if we have loginPageUrl, the next call (getAuthorizationPageContent) is needed only for receiving cookies
            getAuthorizationPageContent(restTemplateWrapperKey, authorizationUrl);
            ResponseEntity<String> loginPageContentResponseEntity = getLoginPageContent(restTemplateWrapperKey, requestContext.getLoginPageUrl());
            List<String> cookies = loginPageContentResponseEntity.getHeaders().get(HttpHeaders.SET_COOKIE);
            MultiValueMap<String, String> loginFormData = buildLoginFormDataForSso(requestContext, loginPageContentResponseEntity.getBody());
            redirectUrlReceivedAfterSuccessfulAuthorization = authorizeAndGetLocationHeader(requestContext, loginFormData, requestContext.getSsoUrl(), cookies);

            ResponseEntity<RESULT> responseEntity = executeRedirectRequestAfterSuccessfulAuthorization(
                requestContext,
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
            redirectUrlReceivedAfterSuccessfulAuthorization = authorizeViaSamlAndGetLocationHeader(restTemplateWrapperKey, responseBodyAsString, samlRedirectUrl);
        } else {
            String authorizationPageContent = getAuthorizationPageContent(restTemplateWrapperKey, authorizationUrl);
            String loginPageUrl = getLoginPageUrlFromAuthorizationPage(authorizationPageContent);
            if (loginPageUrl != null) {
                try {
                    new URL(loginPageUrl);
                } catch (MalformedURLException ex) {
                    log.warn("fetched login page url is not valid: {}. It will be built automatically", loginPageUrl);
                    loginPageUrl = buildDefaultLoginPageUrl(authorizationUrl);
                    log.info("built login page url: {}", loginPageUrl);
                }
                ResponseEntity<String> loginPageContentResponseEntity = getLoginPageContent(restTemplateWrapperKey, loginPageUrl);
                MultiValueMap<String, String> loginFormData = buildLoginFormDataForSso(requestContext, loginPageContentResponseEntity.getBody());
                redirectUrlReceivedAfterSuccessfulAuthorization = authorizeAndGetLocationHeader(requestContext, loginFormData, requestContext.getSsoUrl(), null);
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
                redirectUrlReceivedAfterSuccessfulAuthorization = authorizeAndGetLocationHeader(requestContext, loginFormData, loginUrl, null);
            }
        }

        return executeRedirectRequestAfterSuccessfulAuthorization(
            requestContext,
            restTemplateWrapperKey,
            redirectUrlReceivedAfterSuccessfulAuthorization,
            path,
            signature,
            additionalHeaders,
            responseType
        );
    }

    private void authorizeViaCustomIdpProvider(RequestContext requestContext, String authorizationUrl) throws URISyntaxException {
        RestTemplateWrapper restTemplateWrapper = restTemplateWrapperHolder.getOrCreateRestTemplateWrapperSingleton(requestContext.getRestTemplateWrapperKey());

        String authorizationBaseUrl = getBaseUrl(authorizationUrl);

        List<String> cookies = new ArrayList<>();
        String samlRequestId = initiateSamlRequest(requestContext, authorizationBaseUrl, cookies);
        String signedSamlResponse = getSignedSamlResponse(restTemplateWrapper, requestContext, samlRequestId);
        authenticateUsingSamlResponse(restTemplateWrapper, requestContext, signedSamlResponse, authorizationBaseUrl, cookies);
    }

    private String getBaseUrl(String url) throws URISyntaxException {
        URI uri = new URI(url);
        String protocol = uri.getScheme();
        String authority = uri.getAuthority();
        return String.format("%s://%s", protocol, authority);
    }

    private String initiateSamlRequest(RequestContext requestContext, String authorizationBaseUrl, List<String> cookies) throws URISyntaxException {
        String loginPageUrl = calculateLoginPageUrlForSaml(requestContext, authorizationBaseUrl);

        RestTemplate restTemplate = restTemplateWrapperFactory.createRestTemplateWrapperDisablingRedirect().getRestTemplate();

        ResponseEntity<String> responseEntity = restTemplate.exchange(new RequestEntity(HttpMethod.GET, new URI(loginPageUrl)), String.class);
        cookies.addAll(responseEntity.getHeaders().getOrEmpty(HttpHeaders.SET_COOKIE));
        URI redirectUrl = responseEntity.getHeaders().getLocation();
        if (redirectUrl == null) {
            throw new ClientIntegrationException(format("Redirect URL is not found. Headers: %s, body: %s", responseEntity.getHeaders(), responseEntity.getBody()));
        }
        if (redirectUrl.toString().contains("/login?error=idp_not_found")) {
            throw new ClientIntegrationException("IdP is not found. Please create a Trust configuration in your SAP cockpit.");
        }

        responseEntity = restTemplate.exchange(new RequestEntity(HttpMethod.GET, redirectUrl), String.class);

        String samlRequest = SamlRequestParser.fetchSamlRequestHeader(responseEntity.getHeaders().getLocation());
        if (samlRequest == null) {
            throw new ClientIntegrationException(format("Can't fetch SAMLRequest parameter. Headers: %s, body: %s", responseEntity.getHeaders(), responseEntity.getBody()));
        }

        return SamlRequestParser.fetchSamlRequestId(samlRequest);
    }

    private String calculateLoginPageUrlForSaml(RequestContext requestContext, String authorizationUrl) {
        if (StringUtils.isNotEmpty(requestContext.getLoginPageUrl())) {
            return requestContext.getLoginPageUrl();
        }
        return String.format("%1$s/saml/discovery?returnIDParam=idp&entityID=%1$s&idp=%2$s&isPassive=true",
            authorizationUrl,
            requestContext.getIdpName()
        );
    }

    private String getSignedSamlResponse(RestTemplateWrapper restTemplateWrapper, RequestContext requestContext, String samlRequestId) throws URISyntaxException {
        SamlResponseSigner samlResponseSigner = requestContext.getSamlResponseSigner();
        //If it's not null, use it. Otherwise, request it via Rest API (relevant for the gradle plugins usage)
        if (samlResponseSigner != null) {
            return samlResponseSigner.sign(requestContext.getFigafAgentId(), samlRequestId);
        } else {
            String accessToken = getAccessTokenForCustomIdp(restTemplateWrapper, requestContext);
            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.setBearerAuth(accessToken);
            RequestEntity requestEntity = new RequestEntity(httpHeaders, HttpMethod.GET, new URI(String.format("%s/%s/%s", requestContext.getSamlUrl(), requestContext.getFigafAgentId(), samlRequestId)));
            ResponseEntity<String> response = restTemplateWrapper.getRestTemplate().exchange(requestEntity, String.class);
            return response.getBody();
        }
    }

    private String getAccessTokenForCustomIdp(RestTemplateWrapper restTemplateWrapper, RequestContext requestContext) throws URISyntaxException {
        String oauthTokenUrl = String.format("%s%s", getBaseUrl(requestContext.getSamlUrl()), "/oauth/token");
        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("grant_type", "client_credentials");
        requestBody.add("scope", "idp:sign");
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        httpHeaders.setBasicAuth(requestContext.getIdpApiClientId(), requestContext.getIdpApiClientSecret());
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(requestBody, httpHeaders);
        ResponseEntity<Map> responseEntity = restTemplateWrapper.getRestTemplate().postForEntity(oauthTokenUrl, request, Map.class);
        return (String) responseEntity.getBody().get("access_token");
    }

    private void authenticateUsingSamlResponse(RestTemplateWrapper restTemplateWrapper, RequestContext requestContext, String signedSamlResponse, String authorizationBaseUrl, List<String> cookies) {
        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("SAMLResponse", signedSamlResponse);
        requestBody.add("RelayState", "cloudfoundry-uaa-sp");
        HttpHeaders httpHeaders = new HttpHeaders();
        if (CollectionUtils.isNotEmpty(cookies)) {
            httpHeaders.add("Cookie", StringUtils.join(cookies, "; "));
        }

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(requestBody, httpHeaders);
        ResponseEntity<String> responseEntity;
        try {
            responseEntity = restTemplateWrapper.getRestTemplate().postForEntity(requestContext.getSsoUrl(), request, String.class);
        } catch (HttpClientErrorException ex) {
            log.error("Can't authenticate using SAML response: ", ex);
            throwSpecificExceptionIfSsoUrlIsWrong(requestContext, ex);
            throw ex;
        }

        URI location = responseEntity.getHeaders().getLocation();
        if (location != null && "/saml_error".equals(location.toString())) {
            ResponseEntity<String> samlErrorResponse = restTemplateWrapper.getRestTemplate().getForEntity(String.format("%s/saml_error", authorizationBaseUrl), String.class);
            StringBuilder errorMessageBuilder = new StringBuilder(format("SAML error happened: %s", samlErrorResponse.getBody()));
            if ("{}".equals(samlErrorResponse.getBody())) {
                errorMessageBuilder.append(". Check if relevant Trust configuration is uploaded to your SAP cockpit. It seems it doesn't match with the configuration in the Figaf app or 'Create Shadow Users During Logon' option is disabled.");
            }
            throw new ClientIntegrationException(errorMessageBuilder.toString());
        }
    }

    private String buildDefaultLoginPageUrl(String authorizationUrl) throws MalformedURLException {
        String loginPageUrl;
        URL authorizationUrlObj = new URL(authorizationUrl);
        StringBuilder loginPageUrlBuilder = new StringBuilder();
        loginPageUrlBuilder.append(authorizationUrlObj.getProtocol()).append("://");
        loginPageUrlBuilder.append(authorizationUrlObj.getAuthority());
        loginPageUrlBuilder.append("/login?login_hint=%7B%22origin%22%3A%22sap.default%22%7D");
        loginPageUrl = loginPageUrlBuilder.toString();
        return loginPageUrl;
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

    private String authorizeAndGetLocationHeader(
        RequestContext requestContext,
        MultiValueMap<String, String> loginFormData,
        String loginUrl,
        List<String> cookies
    ) {
        log.debug("#authorizeAndGetLocationHeader(RequestContext requestContext, MultiValueMap<String, String> loginFormData, String loginUrl, List<String> cookies): {}, {}", requestContext, loginUrl);

        ResponseEntity<String> responseEntity = authorize(requestContext, loginFormData, loginUrl, cookies);
        String location = responseEntity.getHeaders().getFirst("Location");

        //IRT-2657: SAP has split authentication process into two steps
        if (location == null && responseEntity.getBody() != null) {
            loginFormData = buildLoginFormDataForSso(requestContext, responseEntity.getBody());
            responseEntity = authorize(requestContext, loginFormData, loginUrl, cookies);
            location = responseEntity.getHeaders().getFirst("Location");
        }
        if (location == null) {
            throw new ClientIntegrationException(String.format("Can't find 'Location' header in the response. Probably it's authentication issue. Body: %s", responseEntity.getBody()));
        }
        return location;
    }

    private String authorizeViaSamlAndGetLocationHeader(String restTemplateWrapperKey, String responseBodyAsString, String samlRedirectUrl) {
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

    private ResponseEntity<String> authorize(
        RequestContext requestContext,
        MultiValueMap<String, String> map,
        String loginUrl,
        List<String> cookies
    ) {
        if (StringUtils.isEmpty(loginUrl)) {
            loginUrl = DEFAULT_SSO_URL;
        }
        HttpHeaders httpHeaders = new HttpHeaders();
        if (CollectionUtils.isNotEmpty(cookies)) {
            httpHeaders.add("Cookie", StringUtils.join(cookies, "; "));
        }
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, httpHeaders);
        RestTemplateWrapper restTemplateWrapper = restTemplateWrapperHolder.getOrCreateRestTemplateWrapperSingleton(requestContext.getRestTemplateWrapperKey());
        ResponseEntity<String> response = restTemplateWrapper.getRestTemplate().postForEntity(loginUrl, request, String.class);
        if (StringUtils.contains(response.getBody(), "Sorry, we could not authenticate you")) {
            throw new ClientIntegrationException("Login/password are not correct");
        }
        return response;
    }

    private <RESP> ResponseEntity<RESP> executeRedirectRequestAfterSuccessfulAuthorization(
        RequestContext requestContext,
        String restTemplateWrapperKey,
        String url,
        String initialPath,
        String signature,
        HttpHeaders additionalHeaders,
        Class<RESP> responseType
    ) throws Exception {
        log.debug("#executeRedirectRequestAfterSuccessfulAuthorization(RequestContext requestContext, String restTemplateWrapperKey, String url, String initialPath, String signature, HttpHeaders additionalHeaders, Class<T> responseType): {}, {}, {}, {}, {}, {}, {}",
            requestContext, restTemplateWrapperKey, url, initialPath, signature, additionalHeaders, responseType
        );

        String cookie = String.format("fragmentAfterLogin=; locationAfterLogin=%s; signature=%s", URLEncoder.encode(initialPath, "UTF-8"), signature);
        HttpHeaders headers = new HttpHeaders();
        headers.add("Cookie", cookie);
        if (additionalHeaders != null) {
            headers.addAll(additionalHeaders);
        }

        RequestEntity requestEntity = new RequestEntity(headers, HttpMethod.GET, new URI(url));
        RestTemplateWrapper restTemplateWrapper = restTemplateWrapperHolder.getOrCreateRestTemplateWrapperSingleton(restTemplateWrapperKey);

        ResponseEntity<RESP> responseEntity;
        try {
            responseEntity = restTemplateWrapper.getRestTemplate().exchange(requestEntity, responseType);
        } catch (HttpClientErrorException.Forbidden | HttpClientErrorException.NotFound ex) {
            if (requestContext.isUseCustomIdp()) {
                throw new ClientIntegrationException(String.format("Please check that Role Collection Mappings are configured properly. " +
                    "PI_Administrator, PI_Business_Expert and PI_Integration_Developer should be assigned to the Trust Configuration with the attribute 'Groups' and the value 'Admin'. " +
                    "If you have been using the 'cpi-plugin', only PI_Integration_Developer should be assigned to the Trust Configuration with the attribute 'Groups' and the value 'Developer'." +
                    " Error message: %s", ExceptionUtils.getMessage(ex))
                );
            } else {
                throw ex;
            }
        }
        return responseEntity;
    }

    private <RESULT> String getResponseBodyString(ResponseEntity<RESULT> responseEntity) {
        RESULT responseBody = responseEntity.getBody();
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
        if (logOnForm == null) {
            if (doc.getElementById("samlRedirect") != null) {
                throw new ClientIntegrationException(
                    String.format("It looks like the user is using SAP Universal ID. Figaf does not support it at the moment. Please create a user without SAP Universal ID. %s", html)
                );
            } else {
                throw new ClientIntegrationException(String.format("Can't find logOnForm element on the page: %s", html));
            }
        }
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

    private <RESP> ResponseEntity<RESP> executeGetPublicApi(
        RequestContext requestContext,
        String path,
        HttpHeaders httpHeaders,
        Class<RESP> bodyType
    ) {
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

    private <REQ, RESP> ResponseEntity<RESP> processForbiddenHttpClientErrorException(
        HttpClientErrorException.Forbidden ex,
        RestTemplate restTemplate,
        String url,
        String tokenUrl,
        HttpEntity<REQ> requestEntity,
        HttpMethod httpMethod,
        String key,
        String oldToken,
        Class<RESP> bodyType
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
                bodyType
            );
        } else {
            throw ex;
        }
    }

    private <REQ> HttpEntity<REQ> createRequestEntityWithNewCsrfToken(
        RestTemplate restTemplate,
        String url,
        HttpEntity<REQ> requestEntity,
        String tokenKey,
        String oldToken
    ) {
        String csrfToken = csrfTokenHolder.getAndSaveNewCsrfTokenIfNeed(tokenKey, restTemplate, url, oldToken);
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.addAll(requestEntity.getHeaders());
        httpHeaders.put(X_CSRF_TOKEN, singletonList(csrfToken));
        return new HttpEntity<>(requestEntity.getBody(), httpHeaders);
    }

    private void throwSpecificExceptionIfSsoUrlIsWrong(RequestContext requestContext, Exception ex) {
        if (requestContext.isUseCustomIdp() && !requestContext.getSsoUrl().contains("/saml/SSO/")) {
            throw new ClientIntegrationException(String.format("SSO Url '%s' seems to be wrong (it should contain '/saml/SSO/'): %s", requestContext.getSsoUrl(), ExceptionUtils.getMessage(ex)));
        }
    }

    private <RESULT, RESPONSE> RESULT processResponse(
        RequestContext requestContext,
        ResponseHandlerCallback<RESULT, RESPONSE> responseHandlerCallback,
        RESPONSE responseBody
    ) {
        RESULT response;
        try {
            response = responseHandlerCallback.apply(responseBody);
        } catch (ClientIntegrationException ex) {
            throwSpecificExceptionIfSsoUrlIsWrong(requestContext, ex);
            throw ex;
        } catch (Exception ex) {
            log.error("Can't handle response body: ", ex);
            throwSpecificExceptionIfSsoUrlIsWrong(requestContext, ex);
            throw new ClientIntegrationException(ex);
        }
        return response;
    }

    @Getter
    private static class LockStatus {
        final ReentrantLock lock = new ReentrantLock();
        final AtomicInteger waitingThreadCount = new AtomicInteger(0);
        @Setter
        boolean authProcessed = false;
    }
}

