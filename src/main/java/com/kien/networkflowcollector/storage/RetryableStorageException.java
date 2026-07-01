package com.kien.networkflowcollector.storage;

public class RetryableStorageException extends RuntimeException {

    public RetryableStorageException(String message, Throwable cause) {
        super(message, cause);
    }
}
