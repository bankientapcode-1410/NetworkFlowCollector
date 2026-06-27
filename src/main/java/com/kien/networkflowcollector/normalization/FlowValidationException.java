package com.kien.networkflowcollector.normalization;

public class FlowValidationException extends RuntimeException {

    private final String sourceType;
    private final String reason;

    public FlowValidationException(String sourceType, String reason, String message) {
        super(message);
        this.sourceType = sourceType;
        this.reason = reason;
    }

    public String sourceType() {
        return sourceType;
    }

    public String reason() {
        return reason;
    }
}
