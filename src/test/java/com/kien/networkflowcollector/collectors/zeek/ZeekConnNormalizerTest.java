package com.kien.networkflowcollector.collectors.zeek;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ZeekConnNormalizerTest {

    private final ZeekConnNormalizer normalizer = new ZeekConnNormalizer();

    @Test
    void normalizesZeekConnRecord() {
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
        assertThat(flow.sourceType()).isEqualTo("zeek-conn");
        assertThat(flow.exporterIp()).isEqualTo("sensor-1");
        assertThat(flow.ingestTime()).isEqualTo(receivedAt);
    }

    @Test
    void flowIdIsStableForSameZeekUid() {
        RawFlowRecord raw = rawRecord(Instant.parse("2026-06-24T12:00:00Z"));

        assertThat(normalizer.normalize(raw).flowId()).isEqualTo(normalizer.normalize(raw).flowId());
    }

    @Test
    void rejectsUnsupportedSourceType() {
        RawFlowRecord raw =
                new RawFlowRecord(
                        "netflow-v5",
                        "sensor-1",
                        Instant.parse("2026-06-24T12:00:00Z"),
                        Map.of());

        assertThatThrownBy(() -> normalizer.normalize(raw))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported source type");
    }

    private static RawFlowRecord rawRecord(Instant receivedAt) {
        ZeekConnLogDecoder decoder = new ZeekConnLogDecoder();
        for (String line : connMetadata()) {
            decoder.decodeLine(line, "sensor-1", receivedAt);
        }
        return decoder.decodeLine(connLine(), "sensor-1", receivedAt).orElseThrow();
    }

    private static List<String> connMetadata() {
        return List.of(
                "#separator \\x09",
                "#set_separator ,",
                "#empty_field (empty)",
                "#unset_field -",
                "#path conn",
                "#fields ts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents",
                "#types time\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]");
    }

    private static String connLine() {
        return "1700000000.123456\tC8DRrW1\t10.0.0.1\t54321\t192.0.2.10\t443\ttcp\tssl\t1.500000\t100\t200\tSF\t-\t-\t0\tShADadFf\t3\t250\t4\t350\t-";
    }
}
