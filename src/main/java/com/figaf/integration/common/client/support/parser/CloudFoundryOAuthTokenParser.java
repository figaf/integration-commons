package com.figaf.integration.common.client.support.parser;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.figaf.integration.common.client.support.OAuthAccessToken;
import com.figaf.integration.common.exception.ParseAccessTokenException;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.util.Date;
import java.util.Map;

/**
 * @author Klochkov Sergey
 */
@Slf4j
public class CloudFoundryOAuthTokenParser implements OAuthTokenParser {

    private final ObjectMapper jsonMapper = new ObjectMapper();

    @Override
    public OAuthAccessToken parse(String responseBody) {
        try {
            Map<String, Object> bodyObject = jsonMapper.readValue(responseBody, Map.class);
            if (!bodyObject.containsKey("access_token") || !bodyObject.containsKey("expires_in")) {
                throw new ParseAccessTokenException("Can't parse access token, because response body has invalid format");
            }
            return new OAuthAccessToken(
                (String)bodyObject.get("access_token"),
                (Integer) bodyObject.get("expires_in") * 1000,
                (new Date()).getTime()
            );
        } catch (IOException ex) {
            log.error("Can't parse access token: ", ex);
            throw new ParseAccessTokenException("Can't parse access token", ex);
        }
    }

}
