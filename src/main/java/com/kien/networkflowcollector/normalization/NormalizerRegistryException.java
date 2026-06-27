package com.kien.networkflowcollector.normalization;

public class NormalizerRegistryException extends RuntimeException {

    public NormalizerRegistryException(String message) {
        super(message);
    }

    public NormalizerRegistryException(String message, Throwable cause) {
        super(message, cause);
    }
}
