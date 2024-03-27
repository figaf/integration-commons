package com.figaf.integration.common.enums;

import lombok.Getter;

@Getter
public enum TypeOfService {

    CONNECTIVITY("Connectivity Service"),

    DESTINATION("Destination Service");

    private final String title;

    TypeOfService(String title) {
        this.title = title;
    }
}
