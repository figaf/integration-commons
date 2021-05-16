package com.figaf.integration.common.client.support;

import lombok.Getter;

import java.util.Date;

/**
 * @author Klochkov Sergey
 */
@Getter
public class OAuthAccessToken {

    private String value;
    private long expiresIn;
    private long creationDate;

    public OAuthAccessToken(String value, long expiresIn, long creationDate) {
        this.value = value;
        this.expiresIn = expiresIn;
        this.creationDate = creationDate;
    }

    public boolean isExpired() {
        return new Date().getTime() - creationDate > expiresIn;
    }

}
