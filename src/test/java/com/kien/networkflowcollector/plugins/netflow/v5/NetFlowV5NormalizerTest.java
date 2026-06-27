package com.kien.networkflowcollector.plugins.netflow.v5;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import io.netty.buffer.Unpooled;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class NetFlowV5NormalizerTest {

    private final NetFlowV5Normalizer normalizer = new NetFlowV5Normalizer();

    @Test
    void normalizeNetFlowV5Record() {
        Instant receivedAt = Instant.parse("2026-06-24T12:00:00Z");
        RawFlowRecord raw = firstRecord(receivedAt);

        NormalizedFlow flow = normalizer.normalize(raw);

        assertThat(flow.tsStart()).isEqualTo(Instant.parse("2023-11-14T22:13:19.123Z"));
        assertThat(flow.tsEnd()).isEqualTo(Instant.parse("2023-11-14T22:13:19.623Z"));
        assertThat(flow.durationMs()).isEqualTo(500);
        assertThat(flow.srcIp()).isEqualTo("10.0.0.1");
        assertThat(flow.srcPort()).isEqualTo(54_321);
        assertThat(flow.dstIp()).isEqualTo("192.0.2.10");
        assertThat(flow.dstPort()).isEqualTo(443);
        assertThat(flow.protocol()).isEqualTo("tcp");
        assertThat(flow.bytesTotal()).isEqualTo(3_456);
        assertThat(flow.packetsTotal()).isEqualTo(12);
        assertThat(flow.tcpFlags()).isEqualTo(27);
        assertThat(flow.sampled()).isTrue();
        assertThat(flow.samplingRate()).isEqualTo(100);
        assertThat(flow.samplePool()).isNull();
        assertThat(flow.sourceType()).isEqualTo("netflow-v5");
        assertThat(flow.exporterIp()).isEqualTo("198.51.100.7");
        assertThat(flow.ingestTime()).isEqualTo(receivedAt);
        assertThat(flow.srcCountryCode()).isNull();
        assertThat(flow.dstCountryCode()).isNull();
    }

    @Test
    void flowIdIsStableForSameRawRecord() {
        RawFlowRecord raw = firstRecord(Instant.parse("2026-06-24T12:00:00Z"));

        assertThat(normalizer.normalize(raw).flowId()).isEqualTo(normalizer.normalize(raw).flowId());
    }

    @Test
    void nonTcpRecordDoesNotExposeTcpFlags() {
        List<RawFlowRecord> records =
                new NetFlowV5Decoder()
                        .decode(
                                Unpooled.wrappedBuffer(NetFlowV5DecoderTest.packet()),
                                "198.51.100.7",
                                Instant.parse("2026-06-24T12:00:00Z"));

        NormalizedFlow flow = normalizer.normalize(records.get(1));

        assertThat(flow.protocol()).isEqualTo("udp");
        assertThat(flow.tcpFlags()).isNull();
    }

    @Test
    void rejectsUnsupportedSourceType() {
        RawFlowRecord raw =
                new RawFlowRecord(
                        "sflow",
                        "198.51.100.7",
                        Instant.parse("2026-06-24T12:00:00Z"),
                        Map.of());

        assertThatThrownBy(() -> normalizer.normalize(raw))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported source type");
    }

    private static RawFlowRecord firstRecord(Instant receivedAt) {
        return new NetFlowV5Decoder()
                .decode(
                        Unpooled.wrappedBuffer(NetFlowV5DecoderTest.packet()),
                        "198.51.100.7",
                        receivedAt)
                .getFirst();
    }
}
