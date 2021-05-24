package com.figaf.integration.common.client.support;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Date;

/**
 * @author Klochkov Sergey
 */
@AllArgsConstructor
@Getter
public class OAuthAccessToken {

    private final String value;
    private final long expiresIn;
    private final long creationDate;

    public boolean isExpired() {
        return new Date().getTime() - creationDate > expiresIn;
    }

}
