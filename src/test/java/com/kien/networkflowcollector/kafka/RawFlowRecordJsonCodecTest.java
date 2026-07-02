package com.kien.networkflowcollector.kafka;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("RawFlowRecordJsonCodec")
class RawFlowRecordJsonCodecTest {

    private RawFlowRecordJsonCodec codec;
    private static final Instant RECEIVED_AT = Instant.parse("2026-06-19T08:15:30Z");

    @BeforeEach
    void setUp() {
        ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
        codec = new RawFlowRecordJsonCodec(mapper);
    }

    private RawFlowRecord sampleRecord() {
        return new RawFlowRecord(
                "netflow-v5", "10.0.0.1", RECEIVED_AT,
                Map.of("src_ip", "192.168.1.1", "dst_port", 443));
    }

    @Test
    @DisplayName("Encode valid record → produces valid JSON")
    void encode_validRecord_producesValidJson() {
        String json = codec.encode(sampleRecord());

        assertThat(json).isNotBlank();
        assertThat(json).contains("netflow-v5");
        assertThat(json).contains("10.0.0.1");
        assertThat(json).contains("192.168.1.1");
    }

    @Test
    @DisplayName("Decode valid JSON → returns record with correct fields")
    void decode_validJson_returnsRecord() {
        String json = codec.encode(sampleRecord());

        RawFlowRecord decoded = codec.decode(json);

        assertThat(decoded.sourceType()).isEqualTo("netflow-v5");
        assertThat(decoded.exporterIp()).isEqualTo("10.0.0.1");
        assertThat(decoded.fields()).isNotEmpty();
    }

    @Test
    @DisplayName("Encode then decode → round-trip preserves data")
    void encodeAndDecode_roundTrip_preservesData() {
        RawFlowRecord original = sampleRecord();
        String json = codec.encode(original);
        RawFlowRecord decoded = codec.decode(json);

        assertThat(decoded.sourceType()).isEqualTo(original.sourceType());
        assertThat(decoded.exporterIp()).isEqualTo(original.exporterIp());
        assertThat(decoded.receivedAt()).isEqualTo(original.receivedAt());
    }

    @Test
    @DisplayName("Decode fields → keeps source fields in normalizer-compatible JSON types")
    void decode_fieldsRemainNormalizerCompatible() {
        Instant tsStart = Instant.parse("2026-06-19T08:00:00Z");
        RawFlowRecord original = new RawFlowRecord(
                "netflow-v5",
                "10.0.0.1",
                RECEIVED_AT,
                Map.of("ts_start", tsStart, "bytes", 42L, "ratio", new BigDecimal("1.25")));

        RawFlowRecord decoded = codec.decode(codec.encode(original));

        assertThat(decoded.fields().get("ts_start")).hasToString(tsStart.toString());
        assertThat(decoded.fields().get("bytes")).isInstanceOf(Number.class);
        assertThat(decoded.fields().get("ratio")).isEqualTo(new BigDecimal("1.25"));
    }

    @Test
    @DisplayName("Encode uses snake_case naming")
    void encode_snakeCaseNaming() {
        String json = codec.encode(sampleRecord());

        assertThat(json).contains("source_type");
        assertThat(json).contains("exporter_ip");
        assertThat(json).contains("received_at");
    }

    @Test
    @DisplayName("Dates serialized as ISO 8601, not epoch timestamps")
    void encode_datesAsIso8601() {
        String json = codec.encode(sampleRecord());

        // The ISO date string should be present
        assertThat(json).contains("2026-06-19");
        // Should NOT be a bare epoch number
        assertThat(json).doesNotContain("1750320930");
    }

    @Test
    @DisplayName("Invalid JSON → throws RawFlowRecordCodecException")
    void decode_invalidJson_throwsCodecException() {
        assertThatThrownBy(() -> codec.decode("{invalid json!!!"))
                .isInstanceOf(RawFlowRecordCodecException.class);
    }

    @Test
    @DisplayName("encodeDeadLetter → produces valid JSON")
    void encodeDeadLetter_validRecord_producesJson() {
        DeadLetterFlowRecord dlq = new DeadLetterFlowRecord(
                "netflow-v5", "10.0.0.1", RECEIVED_AT, Instant.now(),
                "invalid_record", "parse error", null, "{bad}");

        String json = codec.encodeDeadLetter(dlq);

        assertThat(json).isNotBlank();
        assertThat(json).contains("invalid_record");
        assertThat(json).contains("parse error");
    }

    @Test
    @DisplayName("Null record → NullPointerException")
    void encode_nullRecord_throwsNPE() {
        assertThatThrownBy(() -> codec.encode(null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("Null JSON → NullPointerException")
    void decode_nullJson_throwsNPE() {
        assertThatThrownBy(() -> codec.decode(null))
                .isInstanceOf(NullPointerException.class);
    }
}
