package com.kien.networkflowcollector.plugins.suricata;

public class SuricataDecodeException extends IllegalArgumentException {

    public SuricataDecodeException(String message) {
        super(message);
    }

    public SuricataDecodeException(String message, Throwable cause) {
        super(message, cause);
    }
}
