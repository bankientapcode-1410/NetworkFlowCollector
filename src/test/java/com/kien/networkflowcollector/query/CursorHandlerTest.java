package com.kien.networkflowcollector.query;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.kien.networkflowcollector.storage.FlowCursor;
import com.kien.networkflowcollector.storage.FlowQuery;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("CursorHandler")
class CursorHandlerTest {

    private static final Instant FROM = Instant.parse("2026-06-19T00:00:00Z");
    private static final Instant TO = Instant.parse("2026-06-19T12:00:00Z");
    private static final Instant CURSOR_TS = Instant.parse("2026-06-19T08:15:30.120Z");
    private static final UUID FLOW_ID = UUID.fromString("8f14e45f-ceea-467d-9b2e-3c1a2f9b7c10");

    private final CursorHandler cursorHandler =
            new CursorHandler(new ObjectMapper().registerModule(new JavaTimeModule()), "test-secret");

    @Test
    @DisplayName("round-trips a signed cursor for the same filter")
    void decode_sameFilter_returnsFlowCursor() {
        FlowQuery query = query("443");
        FlowCursor cursor = new FlowCursor(CURSOR_TS, FLOW_ID, 50);

        String token = cursorHandler.encode(cursor, query, FlowQueryBuilder.DEFAULT_SORT);

        assertThat(cursorHandler.decode(token, query, FlowQueryBuilder.DEFAULT_SORT)).isEqualTo(cursor);
    }

    @Test
    @DisplayName("rejects a cursor when filters do not match")
    void decode_filterMismatch_rejectsToken() {
        String token =
                cursorHandler.encode(
                        new FlowCursor(CURSOR_TS, FLOW_ID, 50),
                        query("443"),
                        FlowQueryBuilder.DEFAULT_SORT);

        assertThatThrownBy(
                        () -> cursorHandler.decode(token, query("22"), FlowQueryBuilder.DEFAULT_SORT))
                .isInstanceOf(QueryValidationException.class)
                .hasMessageContaining("cursor is invalid");
    }

    @Test
    @DisplayName("rejects a tampered signature")
    void decode_tamperedSignature_rejectsToken() {
        String token =
                cursorHandler.encode(
                        new FlowCursor(CURSOR_TS, FLOW_ID, 50),
                        query("443"),
                        FlowQueryBuilder.DEFAULT_SORT);

        assertThatThrownBy(() -> cursorHandler.decode(token + "a", query("443"), FlowQueryBuilder.DEFAULT_SORT))
                .isInstanceOf(QueryValidationException.class)
                .hasMessageContaining("cursor is invalid");
    }

    private static FlowQuery query(String dstPort) {
        return new FlowQuery(FROM, TO, null, null, null, Integer.parseInt(dstPort), "tcp", null, 50);
    }
}
