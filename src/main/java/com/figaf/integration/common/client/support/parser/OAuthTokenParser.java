package com.figaf.integration.common.client.support.parser;

import com.figaf.integration.common.client.support.OAuthAccessToken;

import java.io.IOException;

/**
 * @author Klochkov Sergey
 */
public interface OAuthTokenParser {

    OAuthAccessToken parse(String responseBody) throws IOException;

}
