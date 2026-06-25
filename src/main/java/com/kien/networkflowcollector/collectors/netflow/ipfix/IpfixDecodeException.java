package com.kien.networkflowcollector.collectors.netflow.ipfix;

public class IpfixDecodeException extends IllegalArgumentException {

    public IpfixDecodeException(String message) {
        super(message);
    }
}
