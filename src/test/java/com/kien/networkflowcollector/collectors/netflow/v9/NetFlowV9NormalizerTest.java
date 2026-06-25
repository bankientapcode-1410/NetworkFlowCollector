package com.kien.networkflowcollector.collectors.netflow.v9;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import io.netty.buffer.Unpooled;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;

class NetFlowV9NormalizerTest {

    private final NetFlowV9Normalizer normalizer = new NetFlowV9Normalizer();

    @Test
    void normalizeNetFlowV9Record() {
        RawFlowRecord raw =
                new NetFlowV9Decoder()
                        .decode(
                                Unpooled.wrappedBuffer(NetFlowV9DecoderTest.packetWithTemplateAndData()),
                                "198.51.100.7",
                                Instant.parse("2026-06-24T12:00:00Z"))
                        .getFirst();

        NormalizedFlow flow = normalizer.normalize(raw);

        assertThat(flow.tsStart()).isEqualTo(Instant.parse("2023-11-14T22:13:19Z"));
        assertThat(flow.tsEnd()).isEqualTo(Instant.parse("2023-11-14T22:13:19.800Z"));
        assertThat(flow.durationMs()).isEqualTo(800);
        assertThat(flow.srcIp()).isEqualTo("10.0.0.3");
        assertThat(flow.srcPort()).isEqualTo(12_345);
        assertThat(flow.dstIp()).isEqualTo("198.51.100.9");
        assertThat(flow.dstPort()).isEqualTo(443);
        assertThat(flow.protocol()).isEqualTo("tcp");
        assertThat(flow.bytesTotal()).isEqualTo(9_876);
        assertThat(flow.packetsTotal()).isEqualTo(10);
        assertThat(flow.tcpFlags()).isEqualTo(19);
        assertThat(flow.sourceType()).isEqualTo("netflow-v9");
        assertThat(flow.exporterIp()).isEqualTo("198.51.100.7");
    }

    @Test
    void rejectsUnsupportedSourceType() {
        RawFlowRecord raw =
                new RawFlowRecord(
                        "ipfix",
                        "198.51.100.7",
                        Instant.parse("2026-06-24T12:00:00Z"),
                        Map.of());

        assertThatThrownBy(() -> normalizer.normalize(raw))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported source type");
    }
}
