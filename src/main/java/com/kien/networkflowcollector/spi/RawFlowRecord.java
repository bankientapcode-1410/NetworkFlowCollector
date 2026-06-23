package com.kien.networkflowcollector.spi;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;

public record RawFlowRecord(
        String sourceType, String exporterIp, Instant receivedAt, Map<String, Object> fields) {

    public RawFlowRecord {
        Objects.requireNonNull(sourceType, "sourceType");
        Objects.requireNonNull(exporterIp, "exporterIp");
        Objects.requireNonNull(receivedAt, "receivedAt");
        fields = Map.copyOf(Objects.requireNonNull(fields, "fields"));
    }
}
