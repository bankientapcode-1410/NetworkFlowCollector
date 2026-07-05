package com.kien.networkflowcollector.plugins.rest;

class RestIngestValidationException extends RuntimeException {

    RestIngestValidationException(String message) {
        super(message);
    }

    RestIngestValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
