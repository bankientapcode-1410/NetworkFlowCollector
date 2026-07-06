package com.kien.networkflowcollector.query;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.kien.networkflowcollector.storage.AggQuery;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("FlowQueryBuilder")
class FlowQueryBuilderTest {

    private final FlowQueryBuilder builder = new FlowQueryBuilder();

    @Test
    @DisplayName("builds normalized flow filters and default limit")
    void flowQuery_validRequest_buildsFilter() {
        FlowQueryBuilder.BuiltFlowQuery built =
                builder.flowQuery(
                        "2026-06-19T00:00:00Z",
                        "2026-06-19T12:00:00Z",
                        "10.20.0.0/16",
                        null,
                        "93.184.216.34",
                        "443",
                        "TCP",
                        "netflow-v5",
                        null,
                        null,
                        false);

        assertThat(built.query().dstPort()).isEqualTo(443);
        assertThat(built.query().protocol()).isEqualTo("tcp");
        assertThat(built.query().limit()).isEqualTo(FlowQueryBuilder.DEFAULT_FLOW_LIMIT);
        assertThat(built.sort()).isEqualTo(FlowQueryBuilder.DEFAULT_SORT);
    }

    @Test
    @DisplayName("keeps limit unset when a cursor supplies page size")
    void flowQuery_cursorWithoutLimit_defersLimitToCursor() {
        FlowQueryBuilder.BuiltFlowQuery built =
                builder.flowQuery(
                        "2026-06-19T00:00:00Z",
                        "2026-06-19T12:00:00Z",
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        true);

        assertThat(built.query().limit()).isZero();
    }

    @Test
    @DisplayName("rejects invalid time ranges")
    void flowQuery_invalidTimeRange_rejectsRequest() {
        assertThatThrownBy(
                        () -> builder.flowQuery(
                                "2026-06-19T12:00:00Z",
                                "2026-06-19T00:00:00Z",
                                null,
                                null,
                                null,
                                null,
                                null,
                                null,
                                null,
                                null,
                                false))
                .isInstanceOf(QueryValidationException.class)
                .hasMessageContaining("start_time must be before end_time");
    }

    @Test
    @DisplayName("rejects invalid port filters")
    void flowQuery_invalidPort_rejectsRequest() {
        assertThatThrownBy(
                        () -> builder.flowQuery(
                                "2026-06-19T00:00:00Z",
                                "2026-06-19T12:00:00Z",
                                null,
                                "70000",
                                null,
                                null,
                                null,
                                null,
                                null,
                                null,
                                false))
                .isInstanceOf(QueryValidationException.class)
                .hasMessageContaining("src_port must be between 0 and 65535");
    }

    @Test
    @DisplayName("builds aggregation query with required metric")
    void aggregationQuery_validRequest_buildsQuery() {
        FlowQueryBuilder.BuiltAggregationQuery built =
                builder.aggregationQuery(
                        "2026-06-19T00:00:00Z", "2026-06-19T12:00:00Z", "packets", "5");

        assertThat(built.query().metric()).isEqualTo(AggQuery.Metric.PACKETS);
        assertThat(built.query().limit()).isEqualTo(5);
        assertThat(built.metric()).isEqualTo("packets");
    }

    @Test
    @DisplayName("rejects aggregation requests without metric")
    void aggregationQuery_missingMetric_rejectsRequest() {
        assertThatThrownBy(
                        () -> builder.aggregationQuery(
                                "2026-06-19T00:00:00Z", "2026-06-19T12:00:00Z", null, null))
                .isInstanceOf(QueryValidationException.class)
                .hasMessageContaining("metric is required");
    }
}
