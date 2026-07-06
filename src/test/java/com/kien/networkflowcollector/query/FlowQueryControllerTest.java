package com.kien.networkflowcollector.query;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.storage.AggBucket;
import com.kien.networkflowcollector.storage.AggQuery;
import com.kien.networkflowcollector.storage.FlowCursor;
import com.kien.networkflowcollector.storage.FlowQuery;
import com.kien.networkflowcollector.storage.FlowSlice;
import com.kien.networkflowcollector.storage.FlowStore;
import com.kien.networkflowcollector.storage.WriteReceipt;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@DisplayName("FlowQueryController")
class FlowQueryControllerTest {

    private static final Instant FROM = Instant.parse("2026-06-19T00:00:00Z");
    private static final Instant TO = Instant.parse("2026-06-19T12:00:00Z");
    private static final Instant FIRST_TS = Instant.parse("2026-06-19T08:15:30.120Z");
    private static final UUID FIRST_ID = UUID.fromString("8f14e45f-ceea-467d-9b2e-3c1a2f9b7c10");

    private final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
    private final CursorHandler cursorHandler = new CursorHandler(objectMapper, "test-secret");
    private final RecordingFlowStore flowStore = new RecordingFlowStore();
    private final MockMvc mockMvc =
            MockMvcBuilders.standaloneSetup(
                            new FlowQueryController(flowStore, new FlowQueryBuilder(), cursorHandler))
                    .build();

    @Test
    @DisplayName("GET /flows returns data and an opaque next cursor")
    void flows_returnsPageWithCursor() throws Exception {
        flowStore.slice =
                new FlowSlice<>(
                        List.of(flow(FIRST_ID, FIRST_TS)),
                        Optional.of(new FlowCursor(FIRST_TS, FIRST_ID, 1)),
                        true);

        mockMvc.perform(
                        get("/flows")
                                .param("start_time", FROM.toString())
                                .param("end_time", TO.toString())
                                .param("dst_port", "443")
                                .param("protocol", "TCP")
                                .param("limit", "1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data[0].flow_id").value(FIRST_ID.toString()))
                .andExpect(jsonPath("$.data[0].dst_port").value(443))
                .andExpect(jsonPath("$.pagination.limit").value(1))
                .andExpect(jsonPath("$.pagination.has_more").value(true))
                .andExpect(jsonPath("$.pagination.next_cursor").isNotEmpty());

        assertThat(flowStore.lastQuery.dstPort()).isEqualTo(443);
        assertThat(flowStore.lastQuery.protocol()).isEqualTo("tcp");
        assertThat(flowStore.lastCursor).isNull();
    }

    @Test
    @DisplayName("GET /flows decodes cursor tokens for the same filter")
    void flows_withCursor_passesDecodedCursorToStore() throws Exception {
        FlowQuery query = new FlowQuery(FROM, TO, null, null, null, 443, "tcp", null, 0);
        String cursor = cursorHandler.encode(new FlowCursor(FIRST_TS, FIRST_ID, 1), query, FlowQueryBuilder.DEFAULT_SORT);

        mockMvc.perform(
                        get("/flows")
                                .param("start_time", FROM.toString())
                                .param("end_time", TO.toString())
                                .param("dst_port", "443")
                                .param("protocol", "tcp")
                                .param("cursor", cursor))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.pagination.limit").value(1));

        assertThat(flowStore.lastCursor).isEqualTo(new FlowCursor(FIRST_TS, FIRST_ID, 1));
    }

    @Test
    @DisplayName("GET /flows rejects cursors for different filters")
    void flows_cursorFilterMismatch_returnsBadRequest() throws Exception {
        FlowQuery query = new FlowQuery(FROM, TO, null, null, null, 443, "tcp", null, 0);
        String cursor = cursorHandler.encode(new FlowCursor(FIRST_TS, FIRST_ID, 1), query, FlowQueryBuilder.DEFAULT_SORT);

        mockMvc.perform(
                        get("/flows")
                                .param("start_time", FROM.toString())
                                .param("end_time", TO.toString())
                                .param("dst_port", "22")
                                .param("protocol", "tcp")
                                .param("cursor", cursor))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("INVALID_CURSOR"));
    }

    @Test
    @DisplayName("GET /flows/{flow_id} returns detail")
    void flowById_existingFlow_returnsDetail() throws Exception {
        flowStore.lookup = Optional.of(flow(FIRST_ID, FIRST_TS));

        mockMvc.perform(get("/flows/{flow_id}", FIRST_ID))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.flow_id").value(FIRST_ID.toString()))
                .andExpect(jsonPath("$.src_ip").value("10.20.30.40"));
    }

    @Test
    @DisplayName("GET /flows/{flow_id} returns 404 when the flow is absent")
    void flowById_missingFlow_returnsNotFound() throws Exception {
        mockMvc.perform(get("/flows/{flow_id}", FIRST_ID))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("FLOW_NOT_FOUND"));
    }

    @Test
    @DisplayName("GET /flows/aggregations/top-talkers returns exact buckets")
    void topTalkers_returnsBuckets() throws Exception {
        flowStore.topTalkers = List.of(new AggBucket("10.20.30.40", 12L, 900L, 40L));

        mockMvc.perform(
                        get("/flows/aggregations/top-talkers")
                                .param("start_time", FROM.toString())
                                .param("end_time", TO.toString())
                                .param("metric", "bytes")
                                .param("limit", "3"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.metric").value("bytes"))
                .andExpect(jsonPath("$.consistency").value("exact"))
                .andExpect(jsonPath("$.window.from").value(FROM.toString()))
                .andExpect(jsonPath("$.results[0].src_ip").value("10.20.30.40"))
                .andExpect(jsonPath("$.results[0].flow_count").value(12));

        assertThat(flowStore.lastAggQuery.limit()).isEqualTo(3);
        assertThat(flowStore.lastAggQuery.metric()).isEqualTo(AggQuery.Metric.BYTES);
    }

    @Test
    @DisplayName("GET /flows/aggregations/top-ports validates metric")
    void topPorts_missingMetric_returnsBadRequest() throws Exception {
        mockMvc.perform(
                        get("/flows/aggregations/top-ports")
                                .param("start_time", FROM.toString())
                                .param("end_time", TO.toString()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("MISSING_PARAMETER"));
    }

    private static NormalizedFlow flow(UUID flowId, Instant tsStart) {
        return new NormalizedFlow(
                flowId,
                tsStart,
                tsStart.plusSeconds(4),
                4000L,
                "10.20.30.40",
                54321,
                "93.184.216.34",
                443,
                "tcp",
                18432L,
                24L,
                27,
                false,
                null,
                null,
                "netflow-v5",
                "10.0.0.1",
                "VN",
                64512L,
                "Example Source",
                "US",
                15133L,
                "Example Network",
                tsStart.plusSeconds(5));
    }

    private static final class RecordingFlowStore implements FlowStore {

        private FlowSlice<NormalizedFlow> slice = new FlowSlice<>(List.of(), Optional.empty(), false);
        private Optional<NormalizedFlow> lookup = Optional.empty();
        private List<AggBucket> topTalkers = List.of();
        private List<AggBucket> topPorts = List.of();
        private FlowQuery lastQuery;
        private FlowCursor lastCursor;
        private AggQuery lastAggQuery;

        @Override
        public WriteReceipt batchInsert(List<NormalizedFlow> flows) {
            return new WriteReceipt(flows.size(), Instant.now());
        }

        @Override
        public FlowSlice<NormalizedFlow> query(FlowQuery filter, FlowCursor cursor) {
            lastQuery = filter;
            lastCursor = cursor;
            return slice;
        }

        @Override
        public Optional<NormalizedFlow> findById(UUID flowId) {
            return lookup;
        }

        @Override
        public List<AggBucket> topTalkers(AggQuery query) {
            lastAggQuery = query;
            return topTalkers;
        }

        @Override
        public List<AggBucket> topPorts(AggQuery query) {
            lastAggQuery = query;
            return topPorts;
        }
    }
}
