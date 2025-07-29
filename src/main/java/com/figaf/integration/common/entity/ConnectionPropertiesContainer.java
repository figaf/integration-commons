package com.figaf.integration.common.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class ConnectionPropertiesContainer {

    private ConnectionProperties connectionPropertiesForIflowTesting;
    private ConnectionProperties connectionPropertiesForPublicApi;
    private ConnectionProperties connectionPropertiesUsernameAndPassword;
}
