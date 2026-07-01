package com.kien.networkflowcollector.plugins.netflow.v5;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.kien.networkflowcollector.spi.RawFlowRecord;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("NetFlowV5Decoder")
class NetFlowV5DecoderTest {

    private static final String EXPORTER_IP = "10.0.0.1";
    private static final Instant RECEIVED_AT = Instant.parse("2026-06-19T10:00:00Z");
    private static final int V5_HEADER_LEN = 24;
    private static final int V5_RECORD_LEN = 48;

    private NetFlowV5Decoder decoder;

    @BeforeEach
    void setUp() {
        decoder = new NetFlowV5Decoder();
    }

    // ── helpers ──────────────────────────────────────────────────

    /**
     * Writes a minimal v5 header into {@code buf} at the current writerIndex.
     */
    private static void writeHeader(ByteBuf buf, int recordCount, long sysUptime,
                                    long unixSecs, long unixNanos, long flowSeq,
                                    int engineType, int engineId,
                                    int samplingMode, int samplingInterval) {
        buf.writeShort(5);                       // version
        buf.writeShort(recordCount);             // count
        buf.writeInt((int) sysUptime);           // sysUptime ms
        buf.writeInt((int) unixSecs);            // unix_secs
        buf.writeInt((int) unixNanos);           // unix_nsecs
        buf.writeInt((int) flowSeq);             // flow_sequence
        buf.writeByte(engineType);
        buf.writeByte(engineId);
        int sampling = ((samplingMode & 0x03) << 14) | (samplingInterval & 0x3fff);
        buf.writeShort(sampling);
    }

    /**
     * Writes one 48-byte v5 flow record.
     */
    private static void writeRecord(ByteBuf buf,
                                    long srcIp, long dstIp, long nextHop,
                                    int inputSnmp, int outputSnmp,
                                    long packets, long bytes,
                                    long firstSwitched, long lastSwitched,
                                    int srcPort, int dstPort,
                                    int tcpFlags, int protocol, int tos,
                                    int srcAs, int dstAs,
                                    int srcMask, int dstMask) {
        buf.writeInt((int) srcIp);               // 0-3   src addr
        buf.writeInt((int) dstIp);               // 4-7   dst addr
        buf.writeInt((int) nextHop);             // 8-11  next hop
        buf.writeShort(inputSnmp);               // 12-13
        buf.writeShort(outputSnmp);              // 14-15
        buf.writeInt((int) packets);             // 16-19
        buf.writeInt((int) bytes);               // 20-23
        buf.writeInt((int) firstSwitched);       // 24-27
        buf.writeInt((int) lastSwitched);        // 28-31
        buf.writeShort(srcPort);                 // 32-33
        buf.writeShort(dstPort);                 // 34-35
        buf.writeByte(0);                        // 36    pad1
        buf.writeByte(tcpFlags);                 // 37
        buf.writeByte(protocol);                 // 38
        buf.writeByte(tos);                      // 39
        buf.writeShort(srcAs);                   // 40-41
        buf.writeShort(dstAs);                   // 42-43
        buf.writeByte(srcMask);                  // 44
        buf.writeByte(dstMask);                  // 45
        buf.writeShort(0);                       // 46-47 pad2
    }

    /** Writes a simple record with known defaults. */
    private static void writeDefaultRecord(ByteBuf buf) {
        writeRecord(buf,
                0x0A000001L, 0xC0A80101L, 0x00000000L,
                1, 2,
                10, 1024,
                5000, 6000,
                54321, 443,
                0x12, 6, 0,
                100, 200,
                24, 16);
    }

    /** Builds a complete v5 packet with N identical default records. */
    private ByteBuf buildPacket(int recordCount) {
        ByteBuf buf = Unpooled.buffer(V5_HEADER_LEN + recordCount * V5_RECORD_LEN);
        writeHeader(buf, recordCount, 100_000L, 1718784000L, 0L, 42L, 1, 2, 0, 0);
        for (int i = 0; i < recordCount; i++) {
            writeDefaultRecord(buf);
        }
        return buf;
    }

    // ── tests ───────────────────────────────────────────────────

    @Test
    @DisplayName("Valid packet with 2 records → returns 2 RawFlowRecords")
    void decode_validPacketWith2Records_returns2RawFlowRecords() {
        ByteBuf packet = buildPacket(2);

        List<RawFlowRecord> records = decoder.decode(packet, EXPORTER_IP, RECEIVED_AT);

        assertThat(records).hasSize(2);
        assertThat(records).allSatisfy(r -> {
            assertThat(r.sourceType()).isEqualTo("netflow-v5");
            assertThat(r.exporterIp()).isEqualTo(EXPORTER_IP);
            assertThat(r.receivedAt()).isEqualTo(RECEIVED_AT);
        });
    }

    @Test
    @DisplayName("Single record → all fields extracted correctly")
    void decode_singleRecord_returnsCorrectFields() {
        ByteBuf buf = Unpooled.buffer(V5_HEADER_LEN + V5_RECORD_LEN);
        writeHeader(buf, 1, 100_000L, 1718784000L, 0L, 42L, 1, 2, 0, 0);
        writeRecord(buf,
                0x0A000001L, 0xC0A80101L, 0x00000000L,
                1, 2,
                10, 1024,
                5000, 6000,
                54321, 443,
                0x12, 6, 0,
                100, 200,
                24, 16);

        List<RawFlowRecord> records = decoder.decode(buf, EXPORTER_IP, RECEIVED_AT);
        assertThat(records).hasSize(1);

        Map<String, Object> f = records.get(0).fields();
        assertThat(f.get("version")).isEqualTo(5);
        assertThat(f.get("src_ip")).isEqualTo("10.0.0.1");
        assertThat(f.get("dst_ip")).isEqualTo("192.168.1.1");
        assertThat(f.get("src_port")).isEqualTo(54321);
        assertThat(f.get("dst_port")).isEqualTo(443);
        assertThat(f.get("protocol")).isEqualTo("tcp");
        assertThat(f.get("protocol_number")).isEqualTo(6);
        assertThat(f.get("bytes")).isEqualTo(1024L);
        assertThat(f.get("packets")).isEqualTo(10L);
        assertThat(f.get("tcp_flags")).isEqualTo(0x12);
        assertThat(f.get("src_as")).isEqualTo(100);
        assertThat(f.get("dst_as")).isEqualTo(200);
        assertThat(f.get("src_mask")).isEqualTo(24);
        assertThat(f.get("dst_mask")).isEqualTo(16);
        assertThat(f.get("input_snmp")).isEqualTo(1);
        assertThat(f.get("output_snmp")).isEqualTo(2);
        assertThat(f.get("ts_start")).isNotNull();
        assertThat(f.get("ts_end")).isNotNull();
        assertThat(f.get("duration_ms")).isNotNull();
    }

    @Test
    @DisplayName("Packet too short (<24 bytes) → throws NetFlowV5DecodeException")
    void decode_packetTooShort_throwsDecodeException() {
        ByteBuf buf = Unpooled.buffer(10);
        buf.writeBytes(new byte[10]);

        assertThatThrownBy(() -> decoder.decode(buf, EXPORTER_IP, RECEIVED_AT))
                .isInstanceOf(NetFlowV5DecodeException.class)
                .hasMessageContaining("too short");
    }

    @Test
    @DisplayName("Wrong version (9) → throws NetFlowV5DecodeException")
    void decode_wrongVersion_throwsDecodeException() {
        ByteBuf buf = Unpooled.buffer(V5_HEADER_LEN);
        buf.writeShort(9);  // wrong version
        buf.writeShort(0);
        buf.writeBytes(new byte[V5_HEADER_LEN - 4]);

        assertThatThrownBy(() -> decoder.decode(buf, EXPORTER_IP, RECEIVED_AT))
                .isInstanceOf(NetFlowV5DecodeException.class)
                .hasMessageContaining("Unsupported");
    }

    @Test
    @DisplayName("Record count > 30 → throws NetFlowV5DecodeException")
    void decode_recordCountExceeds30_throwsDecodeException() {
        ByteBuf buf = Unpooled.buffer(V5_HEADER_LEN);
        buf.writeShort(5);
        buf.writeShort(31); // exceeds MAX_RECORDS=30
        buf.writeBytes(new byte[V5_HEADER_LEN - 4]);

        assertThatThrownBy(() -> decoder.decode(buf, EXPORTER_IP, RECEIVED_AT))
                .isInstanceOf(NetFlowV5DecodeException.class)
                .hasMessageContaining("exceeds 30");
    }

    @Test
    @DisplayName("Truncated packet (header says 2 records, only 1 present) → throws")
    void decode_truncatedPacket_throwsDecodeException() {
        ByteBuf buf = Unpooled.buffer(V5_HEADER_LEN + V5_RECORD_LEN);
        writeHeader(buf, 2, 100_000L, 1718784000L, 0L, 0L, 0, 0, 0, 0);
        writeDefaultRecord(buf); // only 1 record

        assertThatThrownBy(() -> decoder.decode(buf, EXPORTER_IP, RECEIVED_AT))
                .isInstanceOf(NetFlowV5DecodeException.class)
                .hasMessageContaining("truncated");
    }

    @Test
    @DisplayName("Null packet → NullPointerException")
    void decode_nullPacket_throwsNPE() {
        assertThatThrownBy(() -> decoder.decode(null, EXPORTER_IP, RECEIVED_AT))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("Null exporterIp → NullPointerException")
    void decode_nullExporterIp_throwsNPE() {
        ByteBuf buf = buildPacket(1);
        assertThatThrownBy(() -> decoder.decode(buf, null, RECEIVED_AT))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("Null receivedAt → NullPointerException")
    void decode_nullReceivedAt_throwsNPE() {
        ByteBuf buf = buildPacket(1);
        assertThatThrownBy(() -> decoder.decode(buf, EXPORTER_IP, null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("Protocol TCP (6) → protocol name = 'tcp'")
    void decode_protocolTcpSetsCorrectName() {
        ByteBuf buf = Unpooled.buffer(V5_HEADER_LEN + V5_RECORD_LEN);
        writeHeader(buf, 1, 100_000L, 1718784000L, 0L, 0L, 0, 0, 0, 0);
        writeRecord(buf, 0x0A000001L, 0xC0A80101L, 0L, 0, 0, 1, 100,
                5000, 6000, 80, 443, 0x02, 6, 0, 0, 0, 0, 0);

        Map<String, Object> f = decoder.decode(buf, EXPORTER_IP, RECEIVED_AT).get(0).fields();
        assertThat(f.get("protocol")).isEqualTo("tcp");
    }

    @Test
    @DisplayName("Protocol UDP (17) → protocol name = 'udp'")
    void decode_protocolUdpSetsCorrectName() {
        ByteBuf buf = Unpooled.buffer(V5_HEADER_LEN + V5_RECORD_LEN);
        writeHeader(buf, 1, 100_000L, 1718784000L, 0L, 0L, 0, 0, 0, 0);
        writeRecord(buf, 0x0A000001L, 0xC0A80101L, 0L, 0, 0, 1, 100,
                5000, 6000, 80, 53, 0, 17, 0, 0, 0, 0, 0);

        Map<String, Object> f = decoder.decode(buf, EXPORTER_IP, RECEIVED_AT).get(0).fields();
        assertThat(f.get("protocol")).isEqualTo("udp");
    }

    @Test
    @DisplayName("Protocol ICMP (1) → protocol name = 'icmp'")
    void decode_protocolIcmpSetsCorrectName() {
        ByteBuf buf = Unpooled.buffer(V5_HEADER_LEN + V5_RECORD_LEN);
        writeHeader(buf, 1, 100_000L, 1718784000L, 0L, 0L, 0, 0, 0, 0);
        writeRecord(buf, 0x0A000001L, 0xC0A80101L, 0L, 0, 0, 1, 100,
                5000, 6000, 0, 0, 0, 1, 0, 0, 0, 0, 0);

        Map<String, Object> f = decoder.decode(buf, EXPORTER_IP, RECEIVED_AT).get(0).fields();
        assertThat(f.get("protocol")).isEqualTo("icmp");
    }

    @Test
    @DisplayName("Sampling fields parsed from header correctly")
    void decode_samplingFieldsParsedCorrectly() {
        ByteBuf buf = Unpooled.buffer(V5_HEADER_LEN + V5_RECORD_LEN);
        writeHeader(buf, 1, 100_000L, 1718784000L, 0L, 0L, 0, 0, 2, 500);
        writeDefaultRecord(buf);

        Map<String, Object> f = decoder.decode(buf, EXPORTER_IP, RECEIVED_AT).get(0).fields();
        assertThat(f.get("sampling_mode")).isEqualTo(2);
        assertThat(f.get("sampling_interval")).isEqualTo(500);
    }

    @Test
    @DisplayName("flow_sequence from header preserved in record fields")
    void decode_flowSequenceFieldPreserved() {
        ByteBuf buf = Unpooled.buffer(V5_HEADER_LEN + V5_RECORD_LEN);
        writeHeader(buf, 1, 100_000L, 1718784000L, 0L, 42L, 0, 0, 0, 0);
        writeDefaultRecord(buf);

        Map<String, Object> f = decoder.decode(buf, EXPORTER_IP, RECEIVED_AT).get(0).fields();
        assertThat(f.get("flow_sequence")).isEqualTo(42L);
    }

    @Test
    @DisplayName("record_index increments across records (0, 1)")
    void decode_recordIndexIncrements() {
        ByteBuf packet = buildPacket(2);

        List<RawFlowRecord> records = decoder.decode(packet, EXPORTER_IP, RECEIVED_AT);

        assertThat(records.get(0).fields().get("record_index")).isEqualTo(0);
        assertThat(records.get(1).fields().get("record_index")).isEqualTo(1);
    }
}
