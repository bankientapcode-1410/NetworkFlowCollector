package com.kien.networkflowcollector.collectors.suricata;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class SuricataEveDecoderTest {

    private final SuricataEveDecoder decoder = new SuricataEveDecoder();

    @Test
    void decodesEveFlowEvent() {
        Instant receivedAt = Instant.parse("2026-06-24T12:00:00Z");

        RawFlowRecord record =
                decoder.decodeLine(flowEvent(), "sensor-suricata", receivedAt).orElseThrow();

        assertThat(record.sourceType()).isEqualTo("suricata-flow");
        assertThat(record.exporterIp()).isEqualTo("sensor-suricata");
        assertThat(record.receivedAt()).isEqualTo(receivedAt);
        assertThat(record.fields())
                .containsEntry("flow_id", 123456789L)
                .containsEntry("src_ip", "10.0.0.1")
                .containsEntry("src_port", 54321)
                .containsEntry("dst_ip", "192.0.2.10")
                .containsEntry("dst_port", 443)
                .containsEntry("protocol", "tcp")
                .containsEntry("protocol_number", 6)
                .containsEntry("duration_ms", 1500L)
                .containsEntry("bytes", 300L)
                .containsEntry("packets", 7L)
                .containsEntry("app_proto", "tls")
                .containsEntry("flow_state", "closed")
                .containsEntry("flow_reason", "timeout")
                .containsEntry("alerted", false)
                .containsEntry("sampled", false);
        assertThat(record.fields().get("ts_start"))
                .isEqualTo(Instant.parse("2023-11-14T22:13:20.123456Z"));
        assertThat(record.fields().get("ts_end"))
                .isEqualTo(Instant.parse("2023-11-14T22:13:21.623456Z"));
    }

    @Test
    void usesAgeWhenFlowEndIsAbsent() {
        RawFlowRecord record =
                decoder.decodeLine(
                                """
                                {"timestamp":"2023-11-14T22:13:20.000000Z","flow_id":42,"event_type":"flow","src_ip":"10.0.0.2","src_port":53,"dest_ip":"192.0.2.11","dest_port":5353,"proto":"UDP","flow":{"start":"2023-11-14T22:13:20.000000Z","age":0.250,"pkts_toserver":1,"pkts_toclient":2,"bytes_toserver":10,"bytes_toclient":20}}
                                """
                                        .strip(),
                                "sensor-suricata",
                                Instant.parse("2026-06-24T12:00:00Z"))
                        .orElseThrow();

        assertThat(record.fields())
                .containsEntry("protocol", "udp")
                .containsEntry("protocol_number", 17)
                .containsEntry("duration_ms", 250L)
                .containsEntry("bytes", 30L)
                .containsEntry("packets", 3L);
        assertThat(record.fields().get("ts_end")).isEqualTo(Instant.parse("2023-11-14T22:13:20.250Z"));
    }

    @Test
    void ignoresNonFlowEveEvents() {
        Optional<RawFlowRecord> record =
                decoder.decodeLine(
                        """
                        {"timestamp":"2023-11-14T22:13:20.000000+0000","event_type":"alert","src_ip":"10.0.0.1","dest_ip":"192.0.2.10","proto":"TCP"}
                        """
                                .strip(),
                        "sensor-suricata",
                        Instant.parse("2026-06-24T12:00:00Z"));

        assertThat(record).isEmpty();
    }

    @Test
    void rejectsInvalidEveJson() {
        assertThatThrownBy(
                        () ->
                                decoder.decodeLine(
                                        "{",
                                        "sensor-suricata",
                                        Instant.parse("2026-06-24T12:00:00Z")))
                .isInstanceOf(SuricataDecodeException.class)
                .hasMessageContaining("Invalid Suricata EVE JSON line");
    }

    static String flowEvent() {
        return """
                {"timestamp":"2023-11-14T22:13:21.623456+0000","flow_id":123456789,"event_type":"flow","src_ip":"10.0.0.1","src_port":54321,"dest_ip":"192.0.2.10","dest_port":443,"proto":"TCP","app_proto":"tls","flow":{"pkts_toserver":3,"pkts_toclient":4,"bytes_toserver":100,"bytes_toclient":200,"start":"2023-11-14T22:13:20.123456+0000","end":"2023-11-14T22:13:21.623456+0000","age":1.5,"state":"closed","reason":"timeout","alerted":false}}
                """
                .strip();
    }
}
