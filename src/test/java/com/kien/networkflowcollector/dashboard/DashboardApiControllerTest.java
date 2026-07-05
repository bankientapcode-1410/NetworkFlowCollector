package com.kien.networkflowcollector.dashboard;

import static org.assertj.core.api.Assertions.assertThat;

import com.kien.networkflowcollector.metrics.PipelineMetricsPoint;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("DashboardApiController")
class DashboardApiControllerTest {

    @Test
    @DisplayName("fresh short burst rate is not diluted by leading idle seconds")
    void rates_freshShortBurst_usesActiveElapsedSeconds() {
        List<PipelineMetricsPoint> points = pointsEndingAt(Instant.parse("2026-07-05T00:00:59Z"));
        points.set(59, point("2026-07-05T00:00:59Z", 6_000, 3_000, 1_500));

        DashboardApiController.PipelineRates rates = DashboardApiController.rates(points);

        assertThat(rates.collected()).isEqualTo(6_000.0);
        assertThat(rates.normalized()).isEqualTo(3_000.0);
        assertThat(rates.databaseWritten()).isEqualTo(1_500.0);
    }

    @Test
    @DisplayName("idle time after the last event lets the displayed rate decay")
    void rates_shortBurstWithIdleTime_countsElapsedSinceFirstRecentEvent() {
        List<PipelineMetricsPoint> points = pointsEndingAt(Instant.parse("2026-07-05T00:00:59Z"));
        points.set(44, point("2026-07-05T00:00:44Z", 6_000, 0, 0));

        DashboardApiController.PipelineRates rates = DashboardApiController.rates(points);

        assertThat(rates.collected()).isEqualTo(375.0);
    }

    @Test
    @DisplayName("steady traffic over the whole minute still reports the one-minute average")
    void rates_fullMinuteTraffic_keepsMinuteAverage() {
        List<PipelineMetricsPoint> points = pointsEndingAt(Instant.parse("2026-07-05T00:00:59Z"));
        for (int i = 0; i < points.size(); i++) {
            Instant timestamp = Instant.parse("2026-07-05T00:00:00Z").plusSeconds(i);
            points.set(i, new PipelineMetricsPoint(timestamp, 100, 50, 25, Map.of()));
        }

        DashboardApiController.PipelineRates rates = DashboardApiController.rates(points);

        assertThat(rates.collected()).isEqualTo(100.0);
        assertThat(rates.normalized()).isEqualTo(50.0);
        assertThat(rates.databaseWritten()).isEqualTo(25.0);
    }

    private static List<PipelineMetricsPoint> pointsEndingAt(Instant end) {
        List<PipelineMetricsPoint> points = new ArrayList<>();
        Instant start = end.minusSeconds(59);
        for (int i = 0; i < 60; i++) {
            points.add(new PipelineMetricsPoint(start.plusSeconds(i), 0, 0, 0, Map.of()));
        }
        return points;
    }

    private static PipelineMetricsPoint point(String timestamp, long collected, long normalized, long stored) {
        return new PipelineMetricsPoint(Instant.parse(timestamp), collected, normalized, stored, Map.of());
    }
}
