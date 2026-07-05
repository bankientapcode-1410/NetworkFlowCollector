package com.kien.networkflowcollector.metrics;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("PipelineMetrics")
class PipelineMetricsTest {

    private final MutableClock clock = new MutableClock(Instant.parse("2026-07-05T00:00:00Z"));
    private final PipelineMetrics metrics = new PipelineMetrics(clock, null);

    @Test
    @DisplayName("recorded events update totals and the current graph bucket")
    void record_updatesTotalsAndCurrentBucket() {
        metrics.recordCollected(2);
        metrics.recordNormalized();
        metrics.recordStored(3);

        PipelineMetricsSnapshot snapshot = metrics.snapshot();
        PipelineMetricsPoint current = snapshot.points().getLast();

        assertThat(snapshot.collectedTotal()).isEqualTo(2);
        assertThat(snapshot.normalizedTotal()).isEqualTo(1);
        assertThat(snapshot.storedTotal()).isEqualTo(3);
        assertThat(current.timestamp()).isEqualTo(clock.instant());
        assertThat(current.collected()).isEqualTo(2);
        assertThat(current.normalized()).isEqualTo(1);
        assertThat(current.stored()).isEqualTo(3);
        assertThat(current.collectedBySourceType()).containsEntry("unknown", 2L);
    }

    @Test
    @DisplayName("collected events are grouped by source type")
    void recordCollected_tracksSourceTypeTotals() {
        metrics.recordCollected("netflow-v5", 2);
        metrics.recordCollected("suricata-flow", 3);
        metrics.recordCollected("netflow-v5");

        PipelineMetricsSnapshot snapshot = metrics.snapshot();

        assertThat(snapshot.collectedTotal()).isEqualTo(6);
        assertThat(snapshot.collectedBySourceType())
                .containsEntry("netflow-v5", 3L)
                .containsEntry("suricata-flow", 3L);
        assertThat(snapshot.points().getLast().collectedBySourceType())
                .containsEntry("netflow-v5", 3L)
                .containsEntry("suricata-flow", 3L);
    }

    @Test
    @DisplayName("graph window drops buckets older than five minutes while totals remain cumulative")
    void snapshot_excludesExpiredBucketsButKeepsTotals() {
        metrics.recordCollected(5);

        clock.advance(Duration.ofSeconds(PipelineMetrics.WINDOW_SECONDS));
        metrics.recordNormalized(2);

        PipelineMetricsSnapshot snapshot = metrics.snapshot();
        long collectedInWindow = snapshot.points().stream().mapToLong(PipelineMetricsPoint::collected).sum();
        long normalizedInWindow = snapshot.points().stream().mapToLong(PipelineMetricsPoint::normalized).sum();
        long collectedBySourceTypeInWindow = snapshot.points().stream()
                .flatMap(point -> point.collectedBySourceType().values().stream())
                .mapToLong(Long::longValue)
                .sum();

        assertThat(snapshot.collectedTotal()).isEqualTo(5);
        assertThat(snapshot.normalizedTotal()).isEqualTo(2);
        assertThat(collectedInWindow).isZero();
        assertThat(collectedBySourceTypeInWindow).isZero();
        assertThat(normalizedInWindow).isEqualTo(2);
    }

    private static final class MutableClock extends Clock {

        private Instant instant;

        private MutableClock(Instant instant) {
            this.instant = instant;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }

        private void advance(Duration duration) {
            instant = instant.plus(duration);
        }
    }
}
