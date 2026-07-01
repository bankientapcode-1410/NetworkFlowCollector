package com.kien.networkflowcollector.kafka;

import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.time.Instant;
import java.util.Objects;

public record DeadLetterFlowRecord(
        String sourceType,
        String exporterIp,
        Instant receivedAt,
        Instant failedAt,
        String reason,
        String error,
        RawFlowRecord rawRecord,
        String rawPayload) {

    public DeadLetterFlowRecord {
        Objects.requireNonNull(failedAt, "failedAt");
        Objects.requireNonNull(reason, "reason");
    }
}
