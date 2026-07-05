package com.kien.networkflowcollector.metrics;

import java.time.Instant;
import java.util.Map;

public record PipelineMetricsPoint(
        Instant timestamp,
        long collected,
        long normalized,
        long stored,
        Map<String, Long> collectedBySourceType) {

    public PipelineMetricsPoint {
        collectedBySourceType = Map.copyOf(collectedBySourceType);
    }
}
