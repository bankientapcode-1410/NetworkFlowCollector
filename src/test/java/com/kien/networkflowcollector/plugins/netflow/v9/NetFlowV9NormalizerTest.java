package com.kien.networkflowcollector.plugins.netflow.v9;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("NetFlowV9Normalizer")
class NetFlowV9NormalizerTest {

    private static final Instant TS_START = Instant.parse("2026-06-19T08:15:30Z");
    private static final Instant TS_END   = Instant.parse("2026-06-19T08:15:35Z");
    private static final Instant RECEIVED_AT = Instant.parse("2026-06-19T08:15:36Z");

    private NetFlowV9Normalizer normalizer;

    @BeforeEach
    void setUp() {
        normalizer = new NetFlowV9Normalizer();
    }

    private Map<String, Object> validFields() {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("export_time", TS_START);
        f.put("ts_start", TS_START);
        f.put("ts_end", TS_END);
        f.put("duration_ms", 5000L);
        f.put("src_ip", "10.20.30.40");
        f.put("dst_ip", "93.184.216.34");
        f.put("src_port", 54321);
        f.put("dst_port", 443);
        f.put("protocol", "tcp");
        f.put("protocol_number", 6);
        f.put("bytes", 18432L);
        f.put("packets", 24L);
        f.put("tcp_flags", 0x1b);
        f.put("flow_sequence", 42L);
        f.put("record_index", 0);
        f.put("source_id", 100L);
        f.put("template_id", 256);
        return f;
    }

    private RawFlowRecord rawRecord(Map<String, Object> fields) {
        return new RawFlowRecord("netflow-v9", "10.0.0.1", RECEIVED_AT, fields);
    }

    @Test
    @DisplayName("sourceType returns 'netflow-v9'")
    void sourceType_returnsNetflowV9() {
        assertThat(normalizer.sourceType()).isEqualTo("netflow-v9");
    }

    @Test
    @DisplayName("Valid record → NormalizedFlow with correct fields")
    void normalize_validRecord_returnsNormalizedFlow() {
        NormalizedFlow flow = normalizer.normalize(rawRecord(validFields()));

        assertThat(flow.flowId()).isNotNull();
        assertThat(flow.tsStart()).isEqualTo(TS_START);
        assertThat(flow.tsEnd()).isEqualTo(TS_END);
        assertThat(flow.durationMs()).isEqualTo(5000L);
        assertThat(flow.srcIp()).isEqualTo("10.20.30.40");
        assertThat(flow.dstIp()).isEqualTo("93.184.216.34");
        assertThat(flow.srcPort()).isEqualTo(54321);
        assertThat(flow.dstPort()).isEqualTo(443);
        assertThat(flow.protocol()).isEqualTo("tcp");
        assertThat(flow.bytesTotal()).isEqualTo(18432L);
        assertThat(flow.packetsTotal()).isEqualTo(24L);
        assertThat(flow.sourceType()).isEqualTo("netflow-v9");
        assertThat(flow.exporterIp()).isEqualTo("10.0.0.1");
    }

    @Test
    @DisplayName("Missing optional fields → uses defaults")
    void normalize_missingOptionalFields_usesDefaults() {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("export_time", TS_START);
        // No src_port, dst_port, bytes, packets → should default

        NormalizedFlow flow = normalizer.normalize(rawRecord(f));

        assertThat(flow.srcPort()).isEqualTo(0);
        assertThat(flow.dstPort()).isEqualTo(0);
        assertThat(flow.bytesTotal()).isEqualTo(0L);
        assertThat(flow.packetsTotal()).isEqualTo(0L);
        assertThat(flow.srcIp()).isEqualTo("0.0.0.0");
        assertThat(flow.dstIp()).isEqualTo("0.0.0.0");
    }

    @Test
    @DisplayName("Sampling rate > 1 → sampled=true")
    void normalize_samplingRate_setsSampledFlag() {
        Map<String, Object> f = validFields();
        f.put("sampling_rate", 100L);
        f.put("sampled", true);

        NormalizedFlow flow = normalizer.normalize(rawRecord(f));

        assertThat(flow.sampled()).isTrue();
        assertThat(flow.samplingRate()).isEqualTo(100L);
    }

    @Test
    @DisplayName("No sampling fields → unsampled defaults")
    void normalize_noSampling_unsampledDefaults() {
        Map<String, Object> f = validFields();
        // No sampling_rate, sampling_interval, sampled, sample_pool

        NormalizedFlow flow = normalizer.normalize(rawRecord(f));

        assertThat(flow.sampled()).isFalse();
        assertThat(flow.samplingRate()).isNull();
    }

    @Test
    @DisplayName("Same input → same flowId (deterministic)")
    void normalize_flowIdDeterministic() {
        RawFlowRecord raw = rawRecord(validFields());

        UUID id1 = normalizer.normalize(raw).flowId();
        UUID id2 = normalizer.normalize(raw).flowId();

        assertThat(id1).isEqualTo(id2);
    }

    @Test
    @DisplayName("Wrong source type → IllegalArgumentException")
    void normalize_wrongSourceType_throwsException() {
        RawFlowRecord raw = new RawFlowRecord("netflow-v5", "10.0.0.1", RECEIVED_AT, validFields());

        assertThatThrownBy(() -> normalizer.normalize(raw))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported source type");
    }
}
