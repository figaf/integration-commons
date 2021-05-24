package com.figaf.integration.common.client.support.parser;

import com.figaf.integration.common.client.support.OAuthAccessToken;

/**
 * @author Klochkov Sergey
 */
public interface OAuthTokenParser {

    OAuthAccessToken parse(String responseBody);

}
