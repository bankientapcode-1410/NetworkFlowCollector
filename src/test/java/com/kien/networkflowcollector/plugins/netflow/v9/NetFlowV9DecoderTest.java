package com.kien.networkflowcollector.plugins.netflow.v9;

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

@DisplayName("NetFlowV9Decoder")
class NetFlowV9DecoderTest {

    private static final String EXPORTER_IP = "10.0.0.1";
    private static final Instant RECEIVED_AT = Instant.parse("2026-06-19T10:00:00Z");
    private static final long SYS_UPTIME = 100_000L;
    private static final long UNIX_SECS = 1718784000L;
    private static final long FLOW_SEQ = 1L;
    private static final long SOURCE_ID = 100L;
    private static final int V9_HEADER_LEN = 20;

    private NetFlowV9Decoder decoder;

    @BeforeEach
    void setUp() {
        decoder = new NetFlowV9Decoder();
    }

    // ── helpers ──────────────────────────────────────────────────

    private static void writeV9Header(ByteBuf buf, int count, long sysUptime,
                                      long unixSecs, long flowSeq, long sourceId) {
        buf.writeShort(9);
        buf.writeShort(count);
        buf.writeInt((int) sysUptime);
        buf.writeInt((int) unixSecs);
        buf.writeInt((int) flowSeq);
        buf.writeInt((int) sourceId);
    }

    /**
     * Builds a template FlowSet with a single template (id=256) that defines:
     * src_ip(8/4), dst_ip(12/4), src_port(7/2), dst_port(11/2), protocol(4/1),
     * bytes(1/4), packets(2/4), tcp_flags(6/1), first_switched(22/4), last_switched(21/4).
     * Total record length = 4+4+2+2+1+4+4+1+4+4 = 30 bytes.
     */
    private static void writeStdTemplateFlowSet(ByteBuf buf) {
        int[][] fields = {
            {8, 4}, {12, 4}, {7, 2}, {11, 2}, {4, 1},
            {1, 4}, {2, 4}, {6, 1}, {22, 4}, {21, 4}
        };
        int fieldCount = fields.length;
        int flowSetLen = 4 + 4 + fieldCount * 4;   // flowset hdr + tmpl hdr + fields
        buf.writeShort(0);                          // flowSetId = 0 (template)
        buf.writeShort(flowSetLen);
        buf.writeShort(256);                        // templateId
        buf.writeShort(fieldCount);
        for (int[] f : fields) {
            buf.writeShort(f[0]);
            buf.writeShort(f[1]);
        }
    }

    /**
     * Writes a Data FlowSet referencing templateId=256 with one record (30 bytes).
     */
    private static void writeStdDataFlowSet(ByteBuf buf,
                                            long srcIp, long dstIp,
                                            int srcPort, int dstPort,
                                            int proto, long bytes, long packets,
                                            int tcpFlags,
                                            long firstSwitched, long lastSwitched) {
        int recordLen = 30;
        int flowSetLen = 4 + recordLen;
        buf.writeShort(256);                        // flowSetId = templateId
        buf.writeShort(flowSetLen);
        buf.writeInt((int) srcIp);                  // type 8 (4B)
        buf.writeInt((int) dstIp);                  // type 12 (4B)
        buf.writeShort(srcPort);                    // type 7 (2B)
        buf.writeShort(dstPort);                    // type 11 (2B)
        buf.writeByte(proto);                       // type 4 (1B)
        buf.writeInt((int) bytes);                  // type 1 (4B)
        buf.writeInt((int) packets);                // type 2 (4B)
        buf.writeByte(tcpFlags);                    // type 6 (1B)
        buf.writeInt((int) firstSwitched);          // type 22 (4B)
        buf.writeInt((int) lastSwitched);           // type 21 (4B)
    }

    private static void writeDefaultDataFlowSet(ByteBuf buf) {
        writeStdDataFlowSet(buf, 0x0A000001L, 0xC0A80101L,
                54321, 443, 6, 1024L, 10L, 0x12, 5000L, 6000L);
    }

    // ── tests ───────────────────────────────────────────────────

    // Test happy path: template FlowSet followed by data FlowSet in NetFlowV9Decoder.
    @Test
    @DisplayName("Template then Data → returns decoded records")
    void decode_templateThenData_returnsRecords() {
        ByteBuf buf = Unpooled.buffer(256);
        writeV9Header(buf, 1, SYS_UPTIME, UNIX_SECS, FLOW_SEQ, SOURCE_ID);
        writeStdTemplateFlowSet(buf);
        writeDefaultDataFlowSet(buf);

        List<RawFlowRecord> records = decoder.decode(buf, EXPORTER_IP, RECEIVED_AT);

        assertThat(records).hasSize(1);
        Map<String, Object> f = records.get(0).fields();
        assertThat(f.get("src_ip")).isEqualTo("10.0.0.1");
        assertThat(f.get("dst_ip")).isEqualTo("192.168.1.1");
        assertThat(f.get("src_port")).isEqualTo(54321);
        assertThat(f.get("dst_port")).isEqualTo(443);
        assertThat(f.get("protocol")).isEqualTo("tcp");
        assertThat(f.get("bytes")).isEqualTo(1024L);
        assertThat(f.get("packets")).isEqualTo(10L);
        assertThat(f.get("tcp_flags")).isEqualTo(0x12);
        assertThat(records.get(0).sourceType()).isEqualTo("netflow-v9");
    }

    // Test exception: data FlowSet arrives before its template in NetFlowV9Decoder.
    @Test
    @DisplayName("Data before template → throws missing template")
    void decode_dataBeforeTemplate_throwsMissingTemplate() {
        ByteBuf buf = Unpooled.buffer(64);
        writeV9Header(buf, 1, SYS_UPTIME, UNIX_SECS, FLOW_SEQ, SOURCE_ID);
        // Write data FlowSet without prior template
        buf.writeShort(256);    // flowSetId = 256 (data)
        buf.writeShort(8);      // length = 8 (4 header + 4 data)
        buf.writeInt(0xDEADBEEF);

        assertThatThrownBy(() -> decoder.decode(buf, EXPORTER_IP, RECEIVED_AT))
                .isInstanceOf(NetFlowV9DecodeException.class)
                .hasMessageContaining("Missing");
    }

    // Test exception: packet shorter than the NetFlow v9 header in NetFlowV9Decoder.
    @Test
    @DisplayName("Packet too short (<20 bytes) → throws")
    void decode_packetTooShort_throwsDecodeException() {
        ByteBuf buf = Unpooled.buffer(10);
        buf.writeBytes(new byte[10]);

        assertThatThrownBy(() -> decoder.decode(buf, EXPORTER_IP, RECEIVED_AT))
                .isInstanceOf(NetFlowV9DecodeException.class)
                .hasMessageContaining("too short");
    }

    // Test exception: unsupported packet version in NetFlowV9Decoder.
    @Test
    @DisplayName("Wrong version (5) → throws")
    void decode_wrongVersion_throwsDecodeException() {
        ByteBuf buf = Unpooled.buffer(V9_HEADER_LEN);
        buf.writeShort(5); // wrong version
        buf.writeShort(0);
        buf.writeBytes(new byte[V9_HEADER_LEN - 4]);

        assertThatThrownBy(() -> decoder.decode(buf, EXPORTER_IP, RECEIVED_AT))
                .isInstanceOf(NetFlowV9DecodeException.class)
                .hasMessageContaining("Unsupported");
    }

    // Test exception: FlowSet length below the minimum header size in NetFlowV9Decoder.
    @Test
    @DisplayName("FlowSet length < 4 → throws")
    void decode_invalidFlowSetLength_throwsDecodeException() {
        ByteBuf buf = Unpooled.buffer(V9_HEADER_LEN + 4);
        writeV9Header(buf, 0, SYS_UPTIME, UNIX_SECS, FLOW_SEQ, SOURCE_ID);
        buf.writeShort(0);  // flowSetId
        buf.writeShort(2);  // length < 4

        assertThatThrownBy(() -> decoder.decode(buf, EXPORTER_IP, RECEIVED_AT))
                .isInstanceOf(NetFlowV9DecodeException.class)
                .hasMessageContaining("Invalid");
    }

    // Test exception: FlowSet length extends beyond packet end in NetFlowV9Decoder.
    @Test
    @DisplayName("Truncated FlowSet (extends past packet) → throws")
    void decode_truncatedFlowSet_throwsDecodeException() {
        ByteBuf buf = Unpooled.buffer(V9_HEADER_LEN + 4);
        writeV9Header(buf, 0, SYS_UPTIME, UNIX_SECS, FLOW_SEQ, SOURCE_ID);
        buf.writeShort(0);     // flowSetId
        buf.writeShort(100);   // length far beyond packet

        assertThatThrownBy(() -> decoder.decode(buf, EXPORTER_IP, RECEIVED_AT))
                .isInstanceOf(NetFlowV9DecodeException.class)
                .hasMessageContaining("truncated");
    }

    // Test exception: non-zero short template padding in NetFlowV9Decoder.
    @Test
    @DisplayName("Template padding with non-zero bytes → throws")
    void decode_nonZeroTemplatePadding_throwsDecodeException() {
        ByteBuf buf = Unpooled.buffer(V9_HEADER_LEN + 7);
        writeV9Header(buf, 0, SYS_UPTIME, UNIX_SECS, FLOW_SEQ, SOURCE_ID);
        buf.writeShort(0);
        buf.writeShort(7);
        buf.writeByte(0x01);
        buf.writeByte(0x02);
        buf.writeByte(0x03);

        assertThatThrownBy(() -> decoder.decode(buf, EXPORTER_IP, RECEIVED_AT))
                .isInstanceOf(NetFlowV9DecodeException.class)
                .hasMessageContaining("template padding");
    }

    // Test exception: invalid template id/count in NetFlowV9Decoder.
    @Test
    @DisplayName("Invalid template id/count → throws")
    void decode_invalidTemplateIdOrCount_throwsDecodeException() {
        ByteBuf buf = Unpooled.buffer(V9_HEADER_LEN + 8);
        writeV9Header(buf, 0, SYS_UPTIME, UNIX_SECS, FLOW_SEQ, SOURCE_ID);
        buf.writeShort(0);
        buf.writeShort(8);
        buf.writeShort(256);
        buf.writeShort(0);

        assertThatThrownBy(() -> decoder.decode(buf, EXPORTER_IP, RECEIVED_AT))
                .isInstanceOf(NetFlowV9DecodeException.class)
                .hasMessageContaining("template id/count");
    }

    // Test exception: template record does not contain all declared fields in NetFlowV9Decoder.
    @Test
    @DisplayName("Truncated template record → throws")
    void decode_truncatedTemplateRecord_throwsDecodeException() {
        ByteBuf buf = Unpooled.buffer(V9_HEADER_LEN + 12);
        writeV9Header(buf, 0, SYS_UPTIME, UNIX_SECS, FLOW_SEQ, SOURCE_ID);
        buf.writeShort(0);
        buf.writeShort(12);
        buf.writeShort(256);
        buf.writeShort(2);
        buf.writeShort(8);
        buf.writeShort(4);

        assertThatThrownBy(() -> decoder.decode(buf, EXPORTER_IP, RECEIVED_AT))
                .isInstanceOf(NetFlowV9DecodeException.class)
                .hasMessageContaining("template record truncated");
    }

    // Test exception: non-zero short options-template padding in NetFlowV9Decoder.
    @Test
    @DisplayName("Options template padding with non-zero bytes → throws")
    void decode_nonZeroOptionsTemplatePadding_throwsDecodeException() {
        ByteBuf buf = Unpooled.buffer(V9_HEADER_LEN + 5);
        writeV9Header(buf, 0, SYS_UPTIME, UNIX_SECS, FLOW_SEQ, SOURCE_ID);
        buf.writeShort(1);
        buf.writeShort(5);
        buf.writeByte(0x01);

        assertThatThrownBy(() -> decoder.decode(buf, EXPORTER_IP, RECEIVED_AT))
                .isInstanceOf(NetFlowV9DecodeException.class)
                .hasMessageContaining("options template padding");
    }

    // Test exception: invalid options-template field lengths in NetFlowV9Decoder.
    @Test
    @DisplayName("Invalid options template → throws")
    void decode_invalidOptionsTemplate_throwsDecodeException() {
        ByteBuf buf = Unpooled.buffer(V9_HEADER_LEN + 10);
        writeV9Header(buf, 0, SYS_UPTIME, UNIX_SECS, FLOW_SEQ, SOURCE_ID);
        buf.writeShort(1);
        buf.writeShort(10);
        buf.writeShort(257);
        buf.writeShort(2);
        buf.writeShort(4);

        assertThatThrownBy(() -> decoder.decode(buf, EXPORTER_IP, RECEIVED_AT))
                .isInstanceOf(NetFlowV9DecodeException.class)
                .hasMessageContaining("Invalid NetFlow v9 options template");
    }

    // Test exception: options template does not contain all declared fields in NetFlowV9Decoder.
    @Test
    @DisplayName("Truncated options template record → throws")
    void decode_truncatedOptionsTemplateRecord_throwsDecodeException() {
        ByteBuf buf = Unpooled.buffer(V9_HEADER_LEN + 14);
        writeV9Header(buf, 0, SYS_UPTIME, UNIX_SECS, FLOW_SEQ, SOURCE_ID);
        buf.writeShort(1);
        buf.writeShort(14);
        buf.writeShort(257);
        buf.writeShort(4);
        buf.writeShort(4);
        buf.writeShort(1);
        buf.writeShort(4);

        assertThatThrownBy(() -> decoder.decode(buf, EXPORTER_IP, RECEIVED_AT))
                .isInstanceOf(NetFlowV9DecodeException.class)
                .hasMessageContaining("options template record truncated");
    }

    // Test exception: template with zero-length records in NetFlowV9Decoder.
    @Test
    @DisplayName("Invalid data record length → throws")
    void decode_invalidDataRecordLength_throwsDecodeException() {
        ByteBuf buf = Unpooled.buffer(64);
        writeV9Header(buf, 1, SYS_UPTIME, UNIX_SECS, FLOW_SEQ, SOURCE_ID);
        buf.writeShort(0);
        buf.writeShort(12);
        buf.writeShort(256);
        buf.writeShort(1);
        buf.writeShort(8);
        buf.writeShort(0);
        buf.writeShort(256);
        buf.writeShort(4);

        assertThatThrownBy(() -> decoder.decode(buf, EXPORTER_IP, RECEIVED_AT))
                .isInstanceOf(NetFlowV9DecodeException.class)
                .hasMessageContaining("Invalid NetFlow v9 data record length");
    }

    // Test exception: non-zero data FlowSet padding in NetFlowV9Decoder.
    @Test
    @DisplayName("Data FlowSet padding with non-zero bytes → throws")
    void decode_nonZeroDataFlowSetPadding_throwsDecodeException() {
        ByteBuf buf = Unpooled.buffer(128);
        writeV9Header(buf, 1, SYS_UPTIME, UNIX_SECS, FLOW_SEQ, SOURCE_ID);
        buf.writeShort(0);
        buf.writeShort(16);
        buf.writeShort(256);
        buf.writeShort(2);
        buf.writeShort(8);
        buf.writeShort(4);
        buf.writeShort(12);
        buf.writeShort(4);
        buf.writeShort(256);
        buf.writeShort(14);
        buf.writeInt((int) 0x0A000001L);
        buf.writeInt((int) 0xC0A80101L);
        buf.writeByte(0x01);
        buf.writeByte(0x02);

        assertThatThrownBy(() -> decoder.decode(buf, EXPORTER_IP, RECEIVED_AT))
                .isInstanceOf(NetFlowV9DecodeException.class)
                .hasMessageContaining("data FlowSet padding");
    }

    // Test exception: known numeric field length above 8 bytes in NetFlowV9Decoder.
    @Test
    @DisplayName("Unsupported numeric field length → throws")
    void decode_unsupportedNumericFieldLength_throwsIllegalArgumentException() {
        ByteBuf buf = Unpooled.buffer(128);
        writeV9Header(buf, 1, SYS_UPTIME, UNIX_SECS, FLOW_SEQ, SOURCE_ID);
        buf.writeShort(0);
        buf.writeShort(12);
        buf.writeShort(256);
        buf.writeShort(1);
        buf.writeShort(1);
        buf.writeShort(9);
        buf.writeShort(256);
        buf.writeShort(13);
        buf.writeBytes(new byte[9]);

        assertThatThrownBy(() -> decoder.decode(buf, EXPORTER_IP, RECEIVED_AT))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported unsigned integer length");
    }

    // Test happy path: options-template data is skipped by NetFlowV9Decoder.
    @Test
    @DisplayName("Options template → data records for that template are skipped")
    void decode_optionsTemplate_skipsDataRecords() {
        ByteBuf buf = Unpooled.buffer(256);
        writeV9Header(buf, 1, SYS_UPTIME, UNIX_SECS, FLOW_SEQ, SOURCE_ID);

        // Options template FlowSet (flowSetId=1)
        int scopeLen = 4;   // 1 scope field
        int optionLen = 4;  // 1 option field
        int flowSetLen = 4 + 6 + scopeLen + optionLen; // hdr + tmpl hdr(6B) + fields
        buf.writeShort(1);           // flowSetId = options template
        buf.writeShort(flowSetLen);
        buf.writeShort(257);         // templateId
        buf.writeShort(scopeLen);    // scope length
        buf.writeShort(optionLen);   // option length
        buf.writeShort(1);           // scope field type
        buf.writeShort(4);           // scope field length
        buf.writeShort(40);          // option field type
        buf.writeShort(4);           // option field length

        // Data FlowSet for template 257 (will be options → skipped)
        buf.writeShort(257);
        buf.writeShort(12);          // length = 4 hdr + 8 data
        buf.writeInt(0x11111111);
        buf.writeInt(0x22222222);

        List<RawFlowRecord> records = decoder.decode(buf, EXPORTER_IP, RECEIVED_AT);
        assertThat(records).isEmpty();
    }

    // Test happy path: later template definitions replace earlier ones in NetFlowV9Decoder.
    @Test
    @DisplayName("Template update replaces old template")
    void decode_templateUpdate_replacesOldTemplate() {
        // First packet: template 256 with 10 fields (record = 30B)
        ByteBuf buf1 = Unpooled.buffer(256);
        writeV9Header(buf1, 0, SYS_UPTIME, UNIX_SECS, FLOW_SEQ, SOURCE_ID);
        writeStdTemplateFlowSet(buf1);
        decoder.decode(buf1, EXPORTER_IP, RECEIVED_AT);

        // Second packet: redefine template 256 with only 2 fields (src_ip + dst_ip = 8B)
        ByteBuf buf2 = Unpooled.buffer(256);
        writeV9Header(buf2, 1, SYS_UPTIME, UNIX_SECS, FLOW_SEQ, SOURCE_ID);
        int flowSetLen2 = 4 + 4 + 2 * 4;  // hdr + tmpl hdr + 2 fields
        buf2.writeShort(0);
        buf2.writeShort(flowSetLen2);
        buf2.writeShort(256);
        buf2.writeShort(2);
        buf2.writeShort(8);  buf2.writeShort(4);  // src_ip
        buf2.writeShort(12); buf2.writeShort(4);  // dst_ip

        // Data FlowSet with 8-byte record
        buf2.writeShort(256);
        buf2.writeShort(12);  // 4 + 8 bytes
        buf2.writeInt((int) 0x0A0A0A0AL);   // src_ip = 10.10.10.10
        buf2.writeInt((int) 0xC0A80202L);   // dst_ip = 192.168.2.2

        List<RawFlowRecord> records = decoder.decode(buf2, EXPORTER_IP, RECEIVED_AT);
        assertThat(records).hasSize(1);
        assertThat(records.get(0).fields().get("src_ip")).isEqualTo("10.10.10.10");
        assertThat(records.get(0).fields().get("dst_ip")).isEqualTo("192.168.2.2");
    }

    // Test happy path: multiple data FlowSets are all decoded by NetFlowV9Decoder.
    @Test
    @DisplayName("Multiple data FlowSets → all records returned")
    void decode_multipleDataFlowSets_returnsAllRecords() {
        ByteBuf buf = Unpooled.buffer(512);
        writeV9Header(buf, 2, SYS_UPTIME, UNIX_SECS, FLOW_SEQ, SOURCE_ID);
        writeStdTemplateFlowSet(buf);
        writeDefaultDataFlowSet(buf);
        writeStdDataFlowSet(buf, 0xC0A80202L, 0x0A0A0A0AL,
                80, 8080, 17, 2048L, 20L, 0, 7000L, 8000L);

        List<RawFlowRecord> records = decoder.decode(buf, EXPORTER_IP, RECEIVED_AT);
        assertThat(records).hasSize(2);
    }

    // Test happy path: zero trailing packet padding is accepted by NetFlowV9Decoder.
    @Test
    @DisplayName("Trailing zero padding after last FlowSet → accepted")
    void decode_paddingAfterRecords_accepted() {
        ByteBuf buf = Unpooled.buffer(256);
        writeV9Header(buf, 0, SYS_UPTIME, UNIX_SECS, FLOW_SEQ, SOURCE_ID);
        writeStdTemplateFlowSet(buf);
        // Add 3 bytes of zero padding (< 4, so won't be parsed as FlowSet header)
        buf.writeBytes(new byte[3]);

        // Should not throw
        decoder.decode(buf, EXPORTER_IP, RECEIVED_AT);
    }

    // Test exception: non-zero trailing partial FlowSet header in NetFlowV9Decoder.
    @Test
    @DisplayName("Non-zero trailing bytes → throws")
    void decode_nonZeroTrailingBytes_throwsException() {
        ByteBuf buf = Unpooled.buffer(256);
        writeV9Header(buf, 0, SYS_UPTIME, UNIX_SECS, FLOW_SEQ, SOURCE_ID);
        writeStdTemplateFlowSet(buf);
        // Add non-zero trailing bytes
        buf.writeByte(0xFF);
        buf.writeByte(0x01);
        buf.writeByte(0x02);

        assertThatThrownBy(() -> decoder.decode(buf, EXPORTER_IP, RECEIVED_AT))
                .isInstanceOf(NetFlowV9DecodeException.class);
    }

    // Test happy path: IPv4 template fields are decoded to dotted strings in NetFlowV9Decoder.
    @Test
    @DisplayName("IPv4 fields parsed as dotted-decimal strings")
    void decode_ipv4Fields_parsedAsStrings() {
        ByteBuf buf = Unpooled.buffer(256);
        writeV9Header(buf, 1, SYS_UPTIME, UNIX_SECS, FLOW_SEQ, SOURCE_ID);
        writeStdTemplateFlowSet(buf);
        writeStdDataFlowSet(buf, 0xAC100164L, 0x08080808L,
                12345, 80, 6, 512L, 5L, 0x02, 5000L, 6000L);

        Map<String, Object> f = decoder.decode(buf, EXPORTER_IP, RECEIVED_AT).get(0).fields();
        assertThat(f.get("src_ip")).isEqualTo("172.16.1.100");
        assertThat(f.get("dst_ip")).isEqualTo("8.8.8.8");
    }

    // Test happy path: tcp_flags field is decoded as an Integer in NetFlowV9Decoder.
    @Test
    @DisplayName("tcp_flags field parsed as Integer")
    void decode_tcpFlagsField_parsedAsInt() {
        ByteBuf buf = Unpooled.buffer(256);
        writeV9Header(buf, 1, SYS_UPTIME, UNIX_SECS, FLOW_SEQ, SOURCE_ID);
        writeStdTemplateFlowSet(buf);
        writeDefaultDataFlowSet(buf);

        Map<String, Object> f = decoder.decode(buf, EXPORTER_IP, RECEIVED_AT).get(0).fields();
        assertThat(f.get("tcp_flags")).isInstanceOf(Integer.class);
        assertThat(f.get("tcp_flags")).isEqualTo(0x12);
    }

    // Test happy path: switched timestamps produce start/end/duration fields in NetFlowV9Decoder.
    @Test
    @DisplayName("finishRecord computes ts_start, ts_end, duration_ms")
    void decode_finishRecord_computesTsStartTsEndDuration() {
        ByteBuf buf = Unpooled.buffer(256);
        writeV9Header(buf, 1, SYS_UPTIME, UNIX_SECS, FLOW_SEQ, SOURCE_ID);
        writeStdTemplateFlowSet(buf);
        writeStdDataFlowSet(buf, 0x0A000001L, 0xC0A80101L,
                80, 443, 6, 100L, 5L, 0x02, 50_000L, 51_000L);

        Map<String, Object> f = decoder.decode(buf, EXPORTER_IP, RECEIVED_AT).get(0).fields();
        assertThat(f.get("ts_start")).isInstanceOf(Instant.class);
        assertThat(f.get("ts_end")).isInstanceOf(Instant.class);
        assertThat(f.get("duration_ms")).isEqualTo(1000L);  // 51000 - 50000
    }

    // Test happy path: sampling interval field sets sampling metadata in NetFlowV9Decoder.
    @Test
    @DisplayName("Sampling interval field sets sampled flag")
    void decode_samplingIntervalField_setsSampledFlag() {
        ByteBuf buf = Unpooled.buffer(256);
        writeV9Header(buf, 1, SYS_UPTIME, UNIX_SECS, FLOW_SEQ, SOURCE_ID);

        // Template with sampling_interval field (type=34, 2B) added
        int[][] fields = {
            {8, 4}, {12, 4}, {7, 2}, {11, 2}, {4, 1},
            {1, 4}, {2, 4}, {6, 1}, {22, 4}, {21, 4}, {34, 2}
        };
        int fieldCount = fields.length;
        int flowSetLen = 4 + 4 + fieldCount * 4;
        buf.writeShort(0);
        buf.writeShort(flowSetLen);
        buf.writeShort(256);
        buf.writeShort(fieldCount);
        for (int[] f : fields) {
            buf.writeShort(f[0]);
            buf.writeShort(f[1]);
        }

        // Data FlowSet: record = 30 + 2 = 32 bytes
        buf.writeShort(256);
        buf.writeShort(4 + 32);
        buf.writeInt((int) 0x0A000001L);    // src_ip
        buf.writeInt((int) 0xC0A80101L);    // dst_ip
        buf.writeShort(80);                 // src_port
        buf.writeShort(443);                // dst_port
        buf.writeByte(6);                   // protocol = TCP
        buf.writeInt(1024);                 // bytes
        buf.writeInt(10);                   // packets
        buf.writeByte(0x02);                // tcp_flags
        buf.writeInt(50_000);               // first_switched
        buf.writeInt(51_000);               // last_switched
        buf.writeShort(100);                // sampling_interval = 100

        Map<String, Object> f = decoder.decode(buf, EXPORTER_IP, RECEIVED_AT).get(0).fields();
        assertThat(f.get("sampling_interval")).isEqualTo(100L);
        assertThat(f.get("sampling_rate")).isEqualTo(100L);
        assertThat(f.get("sampled")).isEqualTo(true);
    }

    // Test exception: null packet argument in NetFlowV9Decoder.
    @Test
    @DisplayName("Null packet → NPE")
    void decode_nullPacket_throwsNPE() {
        assertThatThrownBy(() -> decoder.decode(null, EXPORTER_IP, RECEIVED_AT))
                .isInstanceOf(NullPointerException.class);
    }

    // Test exception: null exporter IP argument in NetFlowV9Decoder.
    @Test
    @DisplayName("Null exporterIp → NPE")
    void decode_nullExporterIp_throwsNPE() {
        assertThatThrownBy(() -> decoder.decode(Unpooled.buffer(0), null, RECEIVED_AT))
                .isInstanceOf(NullPointerException.class);
    }

    // Test exception: null receivedAt argument in NetFlowV9Decoder.
    @Test
    @DisplayName("Null receivedAt → NPE")
    void decode_nullReceivedAt_throwsNPE() {
        assertThatThrownBy(() -> decoder.decode(Unpooled.buffer(0), EXPORTER_IP, null))
                .isInstanceOf(NullPointerException.class);
    }

    // Test happy path: exporter key includes port when NetFlowV9Decoder receives a port.
    @Test
    @DisplayName("Exporter key includes port when port >= 0")
    void decode_exporterKeyWithPort() {
        ByteBuf buf = Unpooled.buffer(256);
        writeV9Header(buf, 0, SYS_UPTIME, UNIX_SECS, FLOW_SEQ, SOURCE_ID);
        writeStdTemplateFlowSet(buf);
        writeDefaultDataFlowSet(buf);

        // Decode with port=2055 → should use that exporter key internally
        List<RawFlowRecord> records = decoder.decode(buf, EXPORTER_IP, 2055, RECEIVED_AT);
        assertThat(records).hasSize(1);
    }

    // Test happy path: exporter key omits port when NetFlowV9Decoder receives -1.
    @Test
    @DisplayName("Exporter key is just IP when port = -1")
    void decode_exporterKeyWithoutPort() {
        ByteBuf buf = Unpooled.buffer(256);
        writeV9Header(buf, 0, SYS_UPTIME, UNIX_SECS, FLOW_SEQ, SOURCE_ID);
        writeStdTemplateFlowSet(buf);
        writeDefaultDataFlowSet(buf);

        List<RawFlowRecord> records = decoder.decode(buf, EXPORTER_IP, -1, RECEIVED_AT);
        assertThat(records).hasSize(1);
    }
}
