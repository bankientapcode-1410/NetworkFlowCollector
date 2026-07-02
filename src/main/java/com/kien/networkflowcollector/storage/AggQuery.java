package com.kien.networkflowcollector.storage;

import java.time.Instant;

public record AggQuery(Instant from, Instant to, int limit, Metric metric) {

    public AggQuery(Instant from, Instant to, int limit) {
        this(from, to, limit, Metric.BYTES);
    }

    public AggQuery {
        metric = metric == null ? Metric.BYTES : metric;
    }

    public enum Metric {
        BYTES,
        PACKETS,
        FLOWS
    }
}
