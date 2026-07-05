package com.kien.networkflowcollector.plugins.rest;

class RestIngestBackpressureException extends RuntimeException {

    RestIngestBackpressureException(String message, Throwable cause) {
        super(message, cause);
    }
}
