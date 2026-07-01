package com.kien.networkflowcollector.plugins.suricata;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SuricataFlowNormalizerTest {

    private final SuricataFlowNormalizer normalizer = new SuricataFlowNormalizer();

    @Test
    void normalizesSuricataFlowRecord() {
        Instant receivedAt = Instant.parse("2026-06-24T12:00:00Z");
        RawFlowRecord raw = rawRecord(receivedAt);

        NormalizedFlow flow = normalizer.normalize(raw);

        assertThat(flow.tsStart()).isEqualTo(Instant.parse("2023-11-14T22:13:20.123456Z"));
        assertThat(flow.tsEnd()).isEqualTo(Instant.parse("2023-11-14T22:13:21.623456Z"));
        assertThat(flow.durationMs()).isEqualTo(1500);
        assertThat(flow.srcIp()).isEqualTo("10.0.0.1");
        assertThat(flow.srcPort()).isEqualTo(54321);
        assertThat(flow.dstIp()).isEqualTo("192.0.2.10");
        assertThat(flow.dstPort()).isEqualTo(443);
        assertThat(flow.protocol()).isEqualTo("tcp");
        assertThat(flow.bytesTotal()).isEqualTo(300);
        assertThat(flow.packetsTotal()).isEqualTo(7);
        assertThat(flow.tcpFlags()).isNull();
        assertThat(flow.sampled()).isFalse();
        assertThat(flow.sourceType()).isEqualTo("suricata-flow");
        assertThat(flow.exporterIp()).isEqualTo("sensor-suricata");
        assertThat(flow.ingestTime()).isEqualTo(receivedAt);
    }

    @Test
    void flowIdIsStableForSameSuricataFlow() {
        RawFlowRecord raw = rawRecord(Instant.parse("2026-06-24T12:00:00Z"));

        assertThat(normalizer.normalize(raw).flowId()).isEqualTo(normalizer.normalize(raw).flowId());
    }

    @Test
    void rejectsUnsupportedSourceType() {
        RawFlowRecord raw =
                new RawFlowRecord(
                        "zeek-conn",
                        "sensor-suricata",
                        Instant.parse("2026-06-24T12:00:00Z"),
                        Map.of());

        assertThatThrownBy(() -> normalizer.normalize(raw))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported source type");
    }

    private static RawFlowRecord rawRecord(Instant receivedAt) {
        return new SuricataEveDecoder()
                .decodeLine(SuricataEveDecoderTest.flowEvent(), "sensor-suricata", receivedAt)
                .orElseThrow();
    }
}
