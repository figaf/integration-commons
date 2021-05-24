package com.figaf.integration.common.exception;

/**
 * @author Klochkov Sergey
 */
public class ParseAccessTokenException extends RuntimeException {

    public ParseAccessTokenException() {
    }

    public ParseAccessTokenException(String message) {
        super(message);
    }

    public ParseAccessTokenException(Throwable cause) {
        super(cause);
    }

    public ParseAccessTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
