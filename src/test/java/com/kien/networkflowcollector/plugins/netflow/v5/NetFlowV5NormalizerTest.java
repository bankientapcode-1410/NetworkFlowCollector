package com.kien.networkflowcollector.plugins.netflow.v5;

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

@DisplayName("NetFlowV5Normalizer")
class NetFlowV5NormalizerTest {

    private static final Instant TS_START = Instant.parse("2026-06-19T08:15:30Z");
    private static final Instant TS_END   = Instant.parse("2026-06-19T08:15:35Z");
    private static final long DURATION_MS = 5000L;
    private static final Instant RECEIVED_AT = Instant.parse("2026-06-19T08:15:36Z");

    private NetFlowV5Normalizer normalizer;

    @BeforeEach
    void setUp() {
        normalizer = new NetFlowV5Normalizer();
    }

    private Map<String, Object> validFields() {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("ts_start", TS_START);
        f.put("ts_end", TS_END);
        f.put("duration_ms", DURATION_MS);
        f.put("src_ip", "10.20.30.40");
        f.put("dst_ip", "93.184.216.34");
        f.put("src_port", 54321);
        f.put("dst_port", 443);
        f.put("protocol", "tcp");
        f.put("protocol_number", 6);
        f.put("bytes", 18432L);
        f.put("packets", 24L);
        f.put("tcp_flags", 0x1b);
        f.put("sampling_mode", 0);
        f.put("sampling_interval", 0);
        f.put("flow_sequence", 42L);
        f.put("record_index", 0);
        return f;
    }

    private RawFlowRecord rawRecord(Map<String, Object> fields) {
        return new RawFlowRecord("netflow-v5", "10.0.0.1", RECEIVED_AT, fields);
    }

    @Test
    @DisplayName("sourceType returns 'netflow-v5'")
    void sourceType_returnsNetflowV5() {
        assertThat(normalizer.sourceType()).isEqualTo("netflow-v5");
    }

    @Test
    @DisplayName("Valid record → all fields mapped to NormalizedFlow")
    void normalize_validRecord_returnsNormalizedFlow() {
        RawFlowRecord raw = rawRecord(validFields());

        NormalizedFlow flow = normalizer.normalize(raw);

        assertThat(flow.flowId()).isNotNull();
        assertThat(flow.tsStart()).isEqualTo(TS_START);
        assertThat(flow.tsEnd()).isEqualTo(TS_END);
        assertThat(flow.durationMs()).isEqualTo(DURATION_MS);
        assertThat(flow.srcIp()).isEqualTo("10.20.30.40");
        assertThat(flow.dstIp()).isEqualTo("93.184.216.34");
        assertThat(flow.srcPort()).isEqualTo(54321);
        assertThat(flow.dstPort()).isEqualTo(443);
        assertThat(flow.protocol()).isEqualTo("tcp");
        assertThat(flow.bytesTotal()).isEqualTo(18432L);
        assertThat(flow.packetsTotal()).isEqualTo(24L);
        assertThat(flow.sourceType()).isEqualTo("netflow-v5");
        assertThat(flow.exporterIp()).isEqualTo("10.0.0.1");
        assertThat(flow.ingestTime()).isEqualTo(RECEIVED_AT);
    }

    @Test
    @DisplayName("TCP protocol → tcpFlags included")
    void normalize_tcpProtocol_includesTcpFlags() {
        Map<String, Object> f = validFields();
        f.put("protocol_number", 6);
        f.put("tcp_flags", 0x12);

        NormalizedFlow flow = normalizer.normalize(rawRecord(f));

        assertThat(flow.tcpFlags()).isEqualTo(0x12);
    }

    @Test
    @DisplayName("Non-TCP protocol → tcpFlags is null")
    void normalize_nonTcpProtocol_nullTcpFlags() {
        Map<String, Object> f = validFields();
        f.put("protocol_number", 17);
        f.put("protocol", "udp");
        f.put("tcp_flags", 0);

        NormalizedFlow flow = normalizer.normalize(rawRecord(f));

        assertThat(flow.tcpFlags()).isNull();
    }

    @Test
    @DisplayName("Sampled flow → sampled=true, samplingRate set")
    void normalize_sampled_setsRateAndFlag() {
        Map<String, Object> f = validFields();
        f.put("sampling_mode", 1);
        f.put("sampling_interval", 100);

        NormalizedFlow flow = normalizer.normalize(rawRecord(f));

        assertThat(flow.sampled()).isTrue();
        assertThat(flow.samplingRate()).isEqualTo(100L);
    }

    @Test
    @DisplayName("Unsampled flow → sampled=false, samplingRate null")
    void normalize_unsampled_nullRate() {
        Map<String, Object> f = validFields();
        f.put("sampling_mode", 0);
        f.put("sampling_interval", 1);

        NormalizedFlow flow = normalizer.normalize(rawRecord(f));

        assertThat(flow.sampled()).isFalse();
        assertThat(flow.samplingRate()).isNull();
    }

    @Test
    @DisplayName("Same input → same flowId (deterministic UUID)")
    void normalize_flowIdDeterministic() {
        RawFlowRecord raw = rawRecord(validFields());

        UUID id1 = normalizer.normalize(raw).flowId();
        UUID id2 = normalizer.normalize(raw).flowId();

        assertThat(id1).isEqualTo(id2);
    }

    @Test
    @DisplayName("Different inputs → different flowIds")
    void normalize_differentInputs_differentFlowIds() {
        Map<String, Object> f1 = validFields();
        Map<String, Object> f2 = validFields();
        f2.put("src_port", 9999);

        UUID id1 = normalizer.normalize(rawRecord(f1)).flowId();
        UUID id2 = normalizer.normalize(rawRecord(f2)).flowId();

        assertThat(id1).isNotEqualTo(id2);
    }

    @Test
    @DisplayName("Wrong source type → IllegalArgumentException")
    void normalize_wrongSourceType_throwsException() {
        RawFlowRecord raw = new RawFlowRecord("netflow-v9", "10.0.0.1", RECEIVED_AT, validFields());

        assertThatThrownBy(() -> normalizer.normalize(raw))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported source type");
    }

    @Test
    @DisplayName("Missing required field → IllegalArgumentException")
    void normalize_missingRequiredField_throwsException() {
        Map<String, Object> f = validFields();
        f.remove("src_ip");

        assertThatThrownBy(() -> normalizer.normalize(rawRecord(f)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("src_ip");
    }
}
