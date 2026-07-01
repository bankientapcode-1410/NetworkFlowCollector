package com.kien.networkflowcollector.kafka;

public class PublishBackpressureException extends RuntimeException {

    public PublishBackpressureException(String message) {
        super(message);
    }
}
