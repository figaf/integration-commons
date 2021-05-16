package com.figaf.integration.common.entity;

import lombok.*;

import java.net.URI;

/**
 * @author Klochkov Sergey
 */
@NoArgsConstructor
@AllArgsConstructor
@Getter @Setter
@ToString
public class OAuthTokenRequestContext {

    private String clientId;
    private String clientSecret;
    private String oauthTokenUrl;

}
