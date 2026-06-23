package com.kien.networkflowcollector.spi;

import java.time.Instant;

public record CollectorHealth(
        CollectorStatus status, String message, Instant checkedAt, Instant lastRecordAt) {}
