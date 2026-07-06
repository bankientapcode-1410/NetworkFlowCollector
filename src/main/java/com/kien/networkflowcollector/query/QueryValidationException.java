package com.kien.networkflowcollector.query;

public class QueryValidationException extends RuntimeException {

    private final String code;

    public QueryValidationException(String code, String message) {
        super(message);
        this.code = code;
    }

    public String code() {
        return code;
    }
}
