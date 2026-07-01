package com.kien.networkflowcollector.plugins.zeek;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class ZeekConnLogDecoderTest {

    private final ZeekConnLogDecoder decoder = new ZeekConnLogDecoder();

    @Test
    void decodesDefaultConnLogLine() {
        Instant receivedAt = Instant.parse("2026-06-24T12:00:00Z");
        loadConnMetadata();

        RawFlowRecord record =
                decoder.decodeLine(connLine(), "sensor-1", receivedAt).orElseThrow();

        assertThat(record.sourceType()).isEqualTo("zeek-conn");
        assertThat(record.exporterIp()).isEqualTo("sensor-1");
        assertThat(record.receivedAt()).isEqualTo(receivedAt);
        assertThat(record.fields())
                .containsEntry("uid", "C8DRrW1")
                .containsEntry("src_ip", "10.0.0.1")
                .containsEntry("src_port", 54321)
                .containsEntry("dst_ip", "192.0.2.10")
                .containsEntry("dst_port", 443)
                .containsEntry("protocol", "tcp")
                .containsEntry("protocol_number", 6)
                .containsEntry("duration_ms", 1500L)
                .containsEntry("bytes", 300L)
                .containsEntry("packets", 7L)
                .containsEntry("sampled", false);
        assertThat(record.fields().get("ts_start"))
                .isEqualTo(Instant.parse("2023-11-14T22:13:20.123456Z"));
        assertThat(record.fields().get("ts_end"))
                .isEqualTo(Instant.parse("2023-11-14T22:13:21.623456Z"));
    }

    @Test
    void decodesJsonConnLogLine() {
        Instant receivedAt = Instant.parse("2026-06-24T12:00:00Z");

        Optional<RawFlowRecord> record =
                decoder.decodeLine(
                        """
                        {"_path":"conn","ts":1700000000.5,"uid":"Cjson","id.orig_h":"2001:db8::1","id.orig_p":5353,"id.resp_h":"2001:db8::2","id.resp_p":53,"proto":"udp","duration":0.25,"orig_bytes":10,"resp_bytes":20,"orig_pkts":1,"resp_pkts":2}
                        """
                                .strip(),
                        "sensor-json",
                        receivedAt);

        assertThat(record).isPresent();
        assertThat(record.orElseThrow().fields())
                .containsEntry("src_ip", "2001:db8::1")
                .containsEntry("dst_ip", "2001:db8::2")
                .containsEntry("protocol", "udp")
                .containsEntry("protocol_number", 17)
                .containsEntry("duration_ms", 250L)
                .containsEntry("bytes", 30L)
                .containsEntry("packets", 3L);
    }

    @Test
    void ignoresNonConnZeekLogLines() {
        decoder.decodeLine("#separator \\x09", "sensor-1", Instant.now());
        decoder.decodeLine("#path dns", "sensor-1", Instant.now());
        decoder.decodeLine("#fields ts\tuid\tquery", "sensor-1", Instant.now());
        decoder.decodeLine("#types time\tstring\tstring", "sensor-1", Instant.now());

        Optional<RawFlowRecord> record =
                decoder.decodeLine("1700000000.0\tCdns\texample.test", "sensor-1", Instant.now());

        assertThat(record).isEmpty();
    }

    @Test
    void rejectsDataBeforeFieldsMetadata() {
        assertThatThrownBy(() -> decoder.decodeLine(connLine(), "sensor-1", Instant.now()))
                .isInstanceOf(ZeekDecodeException.class)
                .hasMessageContaining("#fields");
    }

    private void loadConnMetadata() {
        for (String line : connMetadata()) {
            decoder.decodeLine(line, "sensor-1", Instant.parse("2026-06-24T12:00:00Z"));
        }
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
