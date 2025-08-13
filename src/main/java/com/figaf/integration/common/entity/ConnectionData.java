package com.figaf.integration.common.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Builder
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class ConnectionData {

    private String publicApiUrl;
    private String host;
    private int port;
    private String protocol;
    private String username;
    private String password;
    private String iflowClientId;
    private String iflowClientSecret;
}
