package com.figaf.integration.common.exception;

/**
 * @author Ilya Nesterov
 */
public class ClientIntegrationException extends RuntimeException {

    protected String possibleSolution;
    protected Object additionalData;

    public ClientIntegrationException() {
    }

    public ClientIntegrationException(String message) {
        super(message);
    }

    public ClientIntegrationException(String message, String possibleSolution) {
        super(message);
        this.possibleSolution = possibleSolution;
    }

    public ClientIntegrationException(String message, Object additionalData) {
        super(message);
        this.additionalData = additionalData;
    }

    public ClientIntegrationException(Throwable cause) {
        super(cause);
    }

    public ClientIntegrationException(String message, Throwable cause) {
        super(message, cause);
    }

    public String getPossibleSolution() {
        return possibleSolution;
    }

    public Object getAdditionalData() {
        return additionalData;
    }
}
