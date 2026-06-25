package com.kien.networkflowcollector.collectors.netflow.ipfix;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import io.netty.buffer.Unpooled;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;

class IpfixNormalizerTest {

    private final IpfixNormalizer normalizer = new IpfixNormalizer();

    @Test
    void normalizeIpfixRecord() {
        RawFlowRecord raw =
                new IpfixDecoder()
                        .decode(
                                Unpooled.wrappedBuffer(IpfixDecoderTest.messageWithTemplateAndData()),
                                "198.51.100.7",
                                Instant.parse("2026-06-24T12:00:00Z"))
                        .getFirst();

        NormalizedFlow flow = normalizer.normalize(raw);

        assertThat(flow.tsStart()).isEqualTo(Instant.parse("2023-11-14T22:13:20.123Z"));
        assertThat(flow.tsEnd()).isEqualTo(Instant.parse("2023-11-14T22:13:20.923Z"));
        assertThat(flow.durationMs()).isEqualTo(800);
        assertThat(flow.srcIp()).isEqualTo("192.0.2.20");
        assertThat(flow.srcPort()).isEqualTo(53);
        assertThat(flow.dstIp()).isEqualTo("203.0.113.30");
        assertThat(flow.dstPort()).isEqualTo(5_353);
        assertThat(flow.protocol()).isEqualTo("udp");
        assertThat(flow.bytesTotal()).isEqualTo(123_456_789);
        assertThat(flow.packetsTotal()).isEqualTo(42);
        assertThat(flow.tcpFlags()).isNull();
        assertThat(flow.sourceType()).isEqualTo("ipfix");
        assertThat(flow.exporterIp()).isEqualTo("198.51.100.7");
    }

    @Test
    void rejectsUnsupportedSourceType() {
        RawFlowRecord raw =
                new RawFlowRecord(
                        "netflow-v9",
                        "198.51.100.7",
                        Instant.parse("2026-06-24T12:00:00Z"),
                        Map.of());

        assertThatThrownBy(() -> normalizer.normalize(raw))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported source type");
    }
}
