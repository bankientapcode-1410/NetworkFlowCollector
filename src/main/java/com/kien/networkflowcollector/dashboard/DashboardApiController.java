package com.kien.networkflowcollector.dashboard;

import com.kien.networkflowcollector.collector.CollectorRegistry;
import com.kien.networkflowcollector.metrics.PipelineMetrics;
import com.kien.networkflowcollector.metrics.PipelineMetricsPoint;
import com.kien.networkflowcollector.metrics.PipelineMetricsSnapshot;
import com.kien.networkflowcollector.spi.CollectorHealth;
import com.kien.networkflowcollector.spi.FlowCollector;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/dashboard")
public class DashboardApiController {

    private static final int RATE_WINDOW_SECONDS = 60;
    private static final int SERIES_BUCKET_SECONDS = 15;

    private final PipelineMetrics metrics;
    private final ObjectProvider<CollectorRegistry> collectorRegistryProvider;

    public DashboardApiController(
            PipelineMetrics metrics, ObjectProvider<CollectorRegistry> collectorRegistryProvider) {
        this.metrics = Objects.requireNonNull(metrics, "metrics");
        this.collectorRegistryProvider =
                Objects.requireNonNull(collectorRegistryProvider, "collectorRegistryProvider");
    }

    @GetMapping("/metrics")
    public DashboardMetricsResponse metrics() {
        PipelineMetricsSnapshot snapshot = metrics.snapshot();
        List<PipelineMetricsPoint> rawPoints = snapshot.points();
        List<PipelinePointResponse> series = bucketPoints(rawPoints).stream()
                .map(point -> new PipelinePointResponse(
                        point.timestamp(),
                        point.collected(),
                        point.normalized(),
                        point.stored(),
                        point.collectedBySourceType()))
                .toList();

        return new DashboardMetricsResponse(
                snapshot.generatedAt(),
                snapshot.windowSeconds(),
                SERIES_BUCKET_SECONDS,
                new PipelineTotals(
                        snapshot.collectedTotal(), snapshot.normalizedTotal(), snapshot.storedTotal()),
                rates(rawPoints),
                series,
                collectedByType(snapshot.collectedBySourceType()),
                collectors());
    }

    private List<PipelineMetricsPoint> bucketPoints(List<PipelineMetricsPoint> points) {
        List<PipelineMetricsPoint> bucketed = new ArrayList<>();
        PipelinePointAccumulator accumulator = null;
        long currentBucketSecond = Long.MIN_VALUE;

        for (PipelineMetricsPoint point : points) {
            long epochSecond = point.timestamp().getEpochSecond();
            long bucketSecond = epochSecond - Math.floorMod(epochSecond, SERIES_BUCKET_SECONDS);
            if (accumulator == null || bucketSecond != currentBucketSecond) {
                if (accumulator != null) {
                    bucketed.add(accumulator.toPoint());
                }
                currentBucketSecond = bucketSecond;
                accumulator = new PipelinePointAccumulator(bucketSecond);
            }
            accumulator.add(point);
        }
        if (accumulator != null) {
            bucketed.add(accumulator.toPoint());
        }
        return bucketed;
    }

    private List<CollectedTypeResponse> collectedByType(Map<String, Long> collectedBySourceType) {
        return collectedBySourceType.entrySet().stream()
                .sorted(Comparator.<Map.Entry<String, Long>>comparingLong(entry -> entry.getValue())
                        .reversed()
                        .thenComparing(Map.Entry::getKey))
                .map(entry -> new CollectedTypeResponse(entry.getKey(), entry.getValue()))
                .toList();
    }

    private PipelineRates rates(List<PipelineMetricsPoint> points) {
        int from = Math.max(0, points.size() - RATE_WINDOW_SECONDS);
        long collected = 0;
        long normalized = 0;
        long stored = 0;
        for (PipelineMetricsPoint point : points.subList(from, points.size())) {
            collected += point.collected();
            normalized += point.normalized();
            stored += point.stored();
        }
        return new PipelineRates(
                collected / (double) RATE_WINDOW_SECONDS,
                normalized / (double) RATE_WINDOW_SECONDS,
                stored / (double) RATE_WINDOW_SECONDS);
    }

    private List<CollectorResponse> collectors() {
        CollectorRegistry registry = collectorRegistryProvider.getIfAvailable();
        if (registry == null) {
            return List.of();
        }
        return registry.collectors().stream().map(this::collector).toList();
    }

    private CollectorResponse collector(FlowCollector collector) {
        try {
            CollectorHealth health = collector.health();
            return new CollectorResponse(
                    collector.type(),
                    collector.supportedSourceTypes().stream().sorted().toList(),
                    health.status().name(),
                    health.message(),
                    health.checkedAt(),
                    health.lastRecordAt());
        } catch (RuntimeException e) {
            return new CollectorResponse(
                    collector.type(),
                    collector.supportedSourceTypes().stream().sorted().toList(),
                    "DOWN",
                    "health check failed: " + e.getMessage(),
                    Instant.now(),
                    null);
        }
    }

    public record DashboardMetricsResponse(
            Instant generatedAt,
            int windowSeconds,
            int seriesBucketSeconds,
            PipelineTotals totals,
            PipelineRates ratesPerSecond,
            List<PipelinePointResponse> series,
            List<CollectedTypeResponse> collectedByType,
            List<CollectorResponse> collectors) {}

    public record PipelineTotals(long collected, long normalized, long databaseWritten) {}

    public record PipelineRates(double collected, double normalized, double databaseWritten) {}

    public record PipelinePointResponse(
            Instant timestamp,
            long collected,
            long normalized,
            long databaseWritten,
            Map<String, Long> collectedBySourceType) {

        public PipelinePointResponse {
            collectedBySourceType = Map.copyOf(collectedBySourceType);
        }
    }

    public record CollectedTypeResponse(String sourceType, long count) {}

    public record CollectorResponse(
            String type,
            List<String> sourceTypes,
            String status,
            String message,
            Instant checkedAt,
            Instant lastRecordAt) {}

    private static final class PipelinePointAccumulator {

        private final long bucketSecond;
        private final Map<String, Long> collectedBySourceType = new HashMap<>();
        private long collected;
        private long normalized;
        private long stored;

        private PipelinePointAccumulator(long bucketSecond) {
            this.bucketSecond = bucketSecond;
        }

        private void add(PipelineMetricsPoint point) {
            collected += point.collected();
            normalized += point.normalized();
            stored += point.stored();
            point.collectedBySourceType()
                    .forEach((sourceType, count) -> collectedBySourceType.merge(sourceType, count, Long::sum));
        }

        private PipelineMetricsPoint toPoint() {
            return new PipelineMetricsPoint(
                    Instant.ofEpochSecond(bucketSecond), collected, normalized, stored, collectedBySourceType);
        }
    }
}
