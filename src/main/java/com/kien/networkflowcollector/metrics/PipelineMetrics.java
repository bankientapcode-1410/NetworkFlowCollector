package com.kien.networkflowcollector.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.LongAdder;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class PipelineMetrics {

    static final int WINDOW_SECONDS = 300;

    private final Clock clock;
    private final Bucket[] buckets = new Bucket[WINDOW_SECONDS];
    private final LongAdder collectedTotal = new LongAdder();
    private final LongAdder normalizedTotal = new LongAdder();
    private final LongAdder storedTotal = new LongAdder();
    private final ConcurrentMap<String, LongAdder> collectedBySourceType = new ConcurrentHashMap<>();
    private final Counter collectedCounter;
    private final Counter normalizedCounter;
    private final Counter storedCounter;

    @Autowired
    public PipelineMetrics(ObjectProvider<MeterRegistry> meterRegistryProvider) {
        this(Clock.systemUTC(), meterRegistryProvider.getIfAvailable());
    }

    PipelineMetrics(Clock clock, MeterRegistry meterRegistry) {
        this.clock = Objects.requireNonNull(clock, "clock");
        for (int i = 0; i < buckets.length; i++) {
            buckets[i] = new Bucket();
        }
        this.collectedCounter = counter(
                meterRegistry,
                "nfc_pipeline_collected_total",
                "Raw flow records accepted by the collector publisher");
        this.normalizedCounter = counter(
                meterRegistry,
                "nfc_pipeline_normalized_total",
                "Raw flow records successfully normalized");
        this.storedCounter = counter(
                meterRegistry,
                "nfc_pipeline_database_written_total",
                "Normalized flow records successfully written to the database");
    }

    public static PipelineMetrics unregistered() {
        return new PipelineMetrics(Clock.systemUTC(), null);
    }

    public void recordCollected() {
        recordCollected(1);
    }

    public void recordCollected(long count) {
        recordCollected("unknown", count);
    }

    public void recordCollected(String sourceType) {
        recordCollected(sourceType, 1);
    }

    public void recordCollected(String sourceType, long count) {
        if (count <= 0) {
            return;
        }
        String normalizedSourceType = sourceType(sourceType);
        collectedBySourceType.computeIfAbsent(normalizedSourceType, ignored -> new LongAdder()).add(count);
        recordCollectedBucket(normalizedSourceType, count);
    }

    public void recordNormalized() {
        recordNormalized(1);
    }

    public void recordNormalized(long count) {
        record(Stage.NORMALIZED, count);
    }

    public void recordStored(long count) {
        record(Stage.STORED, count);
    }

    public PipelineMetricsSnapshot snapshot() {
        Instant generatedAt = clock.instant();
        long nowSecond = generatedAt.getEpochSecond();
        List<PipelineMetricsPoint> points = new ArrayList<>(WINDOW_SECONDS);
        for (long second = nowSecond - WINDOW_SECONDS + 1; second <= nowSecond; second++) {
            Bucket bucket = buckets[Math.floorMod(second, WINDOW_SECONDS)];
            points.add(bucket.snapshot(second));
        }
        return new PipelineMetricsSnapshot(
                generatedAt,
                WINDOW_SECONDS,
                collectedTotal.sum(),
                normalizedTotal.sum(),
                storedTotal.sum(),
                collectedBySourceTypeSnapshot(),
                points);
    }

    private Map<String, Long> collectedBySourceTypeSnapshot() {
        Map<String, Long> snapshot = new HashMap<>();
        collectedBySourceType.forEach((sourceType, count) -> {
            long total = count.sum();
            if (total > 0) {
                snapshot.put(sourceType, total);
            }
        });
        return snapshot;
    }

    private void record(Stage stage, long count) {
        if (count <= 0) {
            return;
        }
        long second = clock.instant().getEpochSecond();
        Bucket bucket = buckets[Math.floorMod(second, WINDOW_SECONDS)];
        bucket.add(second, stage, count);
        switch (stage) {
            case COLLECTED -> {
                collectedTotal.add(count);
                increment(collectedCounter, count);
            }
            case NORMALIZED -> {
                normalizedTotal.add(count);
                increment(normalizedCounter, count);
            }
            case STORED -> {
                storedTotal.add(count);
                increment(storedCounter, count);
            }
        }
    }

    private void recordCollectedBucket(String sourceType, long count) {
        if (count <= 0) {
            return;
        }
        long second = clock.instant().getEpochSecond();
        Bucket bucket = buckets[Math.floorMod(second, WINDOW_SECONDS)];
        bucket.addCollected(second, sourceType, count);
        collectedTotal.add(count);
        increment(collectedCounter, count);
    }

    private static Counter counter(MeterRegistry meterRegistry, String name, String description) {
        if (meterRegistry == null) {
            return null;
        }
        return Counter.builder(name).description(description).register(meterRegistry);
    }

    private static void increment(Counter counter, long count) {
        if (counter != null) {
            counter.increment(count);
        }
    }

    private static String sourceType(String sourceType) {
        if (sourceType == null || sourceType.isBlank()) {
            return "unknown";
        }
        return sourceType.trim();
    }

    private enum Stage {
        COLLECTED,
        NORMALIZED,
        STORED
    }

    private static final class Bucket {

        private long epochSecond = Long.MIN_VALUE;
        private long collected;
        private long normalized;
        private long stored;
        private final Map<String, Long> collectedBySourceType = new HashMap<>();

        private synchronized void add(long second, Stage stage, long count) {
            resetIfNeeded(second);
            switch (stage) {
                case COLLECTED -> collected += count;
                case NORMALIZED -> normalized += count;
                case STORED -> stored += count;
            }
        }

        private synchronized void addCollected(long second, String sourceType, long count) {
            resetIfNeeded(second);
            collected += count;
            collectedBySourceType.merge(sourceType, count, Long::sum);
        }

        private synchronized PipelineMetricsPoint snapshot(long second) {
            if (epochSecond != second) {
                return new PipelineMetricsPoint(Instant.ofEpochSecond(second), 0, 0, 0, Map.of());
            }
            return new PipelineMetricsPoint(
                    Instant.ofEpochSecond(second), collected, normalized, stored, collectedBySourceType);
        }

        private void resetIfNeeded(long second) {
            if (epochSecond != second) {
                epochSecond = second;
                collected = 0;
                normalized = 0;
                stored = 0;
                collectedBySourceType.clear();
            }
        }
    }
}
