package com.kien.networkflowcollector.metrics;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record PipelineMetricsSnapshot(
        Instant generatedAt,
        int windowSeconds,
        long collectedTotal,
        long normalizedTotal,
        long storedTotal,
        Map<String, Long> collectedBySourceType,
        List<PipelineMetricsPoint> points) {

    public PipelineMetricsSnapshot {
        collectedBySourceType = Map.copyOf(collectedBySourceType);
        points = List.copyOf(points);
    }
}
