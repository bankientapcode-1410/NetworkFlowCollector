package com.kien.networkflowcollector.normalization;

public class UnsupportedSourceTypeException extends RuntimeException {

    private final String sourceType;

    public UnsupportedSourceTypeException(String sourceType) {
        super("Unsupported source type: " + sourceType);
        this.sourceType = sourceType;
    }

    public String sourceType() {
        return sourceType;
    }
}
