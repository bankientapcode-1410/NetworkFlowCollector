package com.kien.networkflowcollector.collectors.zeek;

public class ZeekDecodeException extends IllegalArgumentException {

    public ZeekDecodeException(String message) {
        super(message);
    }

    public ZeekDecodeException(String message, Throwable cause) {
        super(message, cause);
    }
}
