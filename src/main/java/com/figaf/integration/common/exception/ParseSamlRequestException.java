package com.figaf.integration.common.exception;

public class ParseSamlRequestException extends RuntimeException {

    public ParseSamlRequestException() {
    }

    public ParseSamlRequestException(String message) {
        super(message);
    }

    public ParseSamlRequestException(Throwable cause) {
        super(cause);
    }

    public ParseSamlRequestException(String message, Throwable cause) {
        super(message, cause);
    }
}
