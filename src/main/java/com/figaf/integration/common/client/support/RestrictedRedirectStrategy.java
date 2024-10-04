package com.figaf.integration.common.client.support;

import org.apache.hc.client5.http.impl.DefaultRedirectStrategy;
import org.apache.hc.core5.http.*;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.util.Args;

import java.util.Set;

import static org.apache.commons.collections4.SetUtils.hashSet;

public class RestrictedRedirectStrategy extends DefaultRedirectStrategy {

    public static final RestrictedRedirectStrategy INSTANCE = new RestrictedRedirectStrategy();

    private static final Set<String> ALLOWED_FOR_REDIRECT = hashSet("GET", "HEAD");

    @Override
    public boolean isRedirected(
        final HttpRequest request,
        final HttpResponse response,
        final HttpContext context) throws ProtocolException {
        Args.notNull(request, "HTTP request");
        Args.notNull(response, "HTTP response");

        if (!response.containsHeader(HttpHeaders.LOCATION)) {
            return false;
        }
        final int statusCode = response.getCode();
        switch (statusCode) {
            case HttpStatus.SC_MOVED_PERMANENTLY:
            case HttpStatus.SC_SEE_OTHER:
            case HttpStatus.SC_TEMPORARY_REDIRECT:
            case HttpStatus.SC_PERMANENT_REDIRECT:
                return true;
            case HttpStatus.SC_MOVED_TEMPORARILY: {
                return ALLOWED_FOR_REDIRECT.contains(request.getMethod());
            }
            default:
                return false;
        }
    }
}
