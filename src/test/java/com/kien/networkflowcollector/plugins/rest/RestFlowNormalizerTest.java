package com.kien.networkflowcollector.plugins.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.normalization.NormalizedFlowValidator;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class RestFlowNormalizerTest {

    private final RestFlowNormalizer normalizer = new RestFlowNormalizer();

    @Test
    void normalizesRestFlowRecord() {
        Instant receivedAt = Instant.parse("2026-07-05T08:00:00Z");
        RawFlowRecord raw = rawRecord(receivedAt);

        NormalizedFlow flow = normalizer.normalize(raw);

        assertThat(flow.tsStart()).isEqualTo(Instant.parse("2026-07-05T07:59:58Z"));
        assertThat(flow.tsEnd()).isEqualTo(Instant.parse("2026-07-05T08:00:00Z"));
        assertThat(flow.durationMs()).isEqualTo(2_000);
        assertThat(flow.srcIp()).isEqualTo("192.168.2.10");
        assertThat(flow.srcPort()).isEqualTo(52_000);
        assertThat(flow.dstIp()).isEqualTo("10.1.0.20");
        assertThat(flow.dstPort()).isEqualTo(443);
        assertThat(flow.protocol()).isEqualTo("tcp");
        assertThat(flow.bytesTotal()).isEqualTo(9_000);
        assertThat(flow.packetsTotal()).isEqualTo(30);
        assertThat(flow.tcpFlags()).isEqualTo(27);
        assertThat(flow.sampled()).isFalse();
        assertThat(flow.sourceType()).isEqualTo("rest");
        assertThat(flow.exporterIp()).isEqualTo("127.0.0.1");
        assertThat(flow.ingestTime()).isEqualTo(receivedAt);
        new NormalizedFlowValidator().validate(flow);
    }

    @Test
    void flowIdIsStableForSameRestEvent() {
        RawFlowRecord raw = rawRecord(Instant.parse("2026-07-05T08:00:00Z"));

        assertThat(normalizer.normalize(raw).flowId()).isEqualTo(normalizer.normalize(raw).flowId());
    }

    @Test
    void acceptsEpochMillisAndNumericProtocolAliases() {
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("event_id", "rest-epoch-1");
        fields.put("src_ip", "192.168.2.10");
        fields.put("dst_ip", "10.1.0.20");
        fields.put("src_port", 52_000);
        fields.put("dst_port", 53);
        fields.put("proto", 17);
        fields.put("bytes_total", 512);
        fields.put("packets_total", 4);
        fields.put("start", 1_783_240_798_000L);
        fields.put("end", 1_783_240_799_500L);
        RawFlowRecord raw =
                new RawFlowRecord("rest", "127.0.0.1", Instant.parse("2026-07-05T08:00:00Z"), fields);

        NormalizedFlow flow = normalizer.normalize(raw);

        assertThat(flow.protocol()).isEqualTo("udp");
        assertThat(flow.durationMs()).isEqualTo(1_500);
        assertThat(flow.bytesTotal()).isEqualTo(512);
        assertThat(flow.packetsTotal()).isEqualTo(4);
    }

    @Test
    void rejectsUnsupportedSourceType() {
        RawFlowRecord raw =
                new RawFlowRecord("netflow-v5", "127.0.0.1", Instant.parse("2026-07-05T08:00:00Z"), Map.of());

        assertThatThrownBy(() -> normalizer.normalize(raw))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported source type");
    }

    private static RawFlowRecord rawRecord(Instant receivedAt) {
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("event_id", "rest-event-1");
        fields.put("src_ip", "192.168.2.10");
        fields.put("dst_ip", "10.1.0.20");
        fields.put("src_port", 52_000);
        fields.put("dst_port", 443);
        fields.put("protocol", "TCP");
        fields.put("bytes", 9_000);
        fields.put("packets", 30);
        fields.put("tcp_flags", "0x1b");
        fields.put("ts_start", "2026-07-05T07:59:58Z");
        fields.put("ts_end", "2026-07-05T08:00:00Z");
        return new RawFlowRecord("rest", "127.0.0.1", receivedAt, fields);
    }
}
