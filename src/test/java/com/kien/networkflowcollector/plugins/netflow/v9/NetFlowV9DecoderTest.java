package com.kien.networkflowcollector.plugins.netflow.v9;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.kien.networkflowcollector.spi.RawFlowRecord;
import io.netty.buffer.Unpooled;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class NetFlowV9DecoderTest {

    private final NetFlowV9Decoder decoder = new NetFlowV9Decoder();

    @Test
    void decodeTemplateAndDataFlowSetsReturnsRawRecords() {
        Instant receivedAt = Instant.parse("2026-06-24T12:00:00Z");

        List<RawFlowRecord> records =
                decoder.decode(Unpooled.wrappedBuffer(packetWithTemplateAndData()), "198.51.100.7", receivedAt);

        assertThat(records).hasSize(1);
        RawFlowRecord record = records.getFirst();
        assertThat(record.sourceType()).isEqualTo("netflow-v9");
        assertThat(record.exporterIp()).isEqualTo("198.51.100.7");
        assertThat(record.receivedAt()).isEqualTo(receivedAt);

        Map<String, Object> fields = record.fields();
        assertThat(fields)
                .containsEntry("version", 9)
                .containsEntry("packet_record_count", 1)
                .containsEntry("record_index", 0)
                .containsEntry("sys_uptime_ms", 1_000_000L)
                .containsEntry("flow_sequence", 100L)
                .containsEntry("source_id", 123L)
                .containsEntry("template_id", 256)
                .containsEntry("src_ip", "10.0.0.3")
                .containsEntry("dst_ip", "198.51.100.9")
                .containsEntry("src_port", 12_345)
                .containsEntry("dst_port", 443)
                .containsEntry("protocol_number", 6)
                .containsEntry("protocol", "tcp")
                .containsEntry("tcp_flags", 19)
                .containsEntry("bytes", 9_876L)
                .containsEntry("packets", 10L)
                .containsEntry("first_switched_ms", 999_000L)
                .containsEntry("last_switched_ms", 999_800L)
                .containsEntry("ts_start", Instant.parse("2023-11-14T22:13:19Z"))
                .containsEntry("ts_end", Instant.parse("2023-11-14T22:13:19.800Z"))
                .containsEntry("duration_ms", 800L);
    }

    @Test
    void cachesTemplateAcrossPackets() {
        Instant receivedAt = Instant.parse("2026-06-24T12:00:00Z");

        assertThat(decoder.decode(Unpooled.wrappedBuffer(templateOnlyPacket()), "198.51.100.7", receivedAt))
                .isEmpty();

        List<RawFlowRecord> records =
                decoder.decode(Unpooled.wrappedBuffer(dataOnlyPacket()), "198.51.100.7", receivedAt);

        assertThat(records).hasSize(1);
        assertThat(records.getFirst().fields()).containsEntry("src_ip", "10.0.0.3");
    }

    @Test
    void rejectsDataWithoutTemplate() {
        assertThatThrownBy(
                        () ->
                                new NetFlowV9Decoder()
                                        .decode(
                                                Unpooled.wrappedBuffer(dataOnlyPacket()),
                                                "198.51.100.7",
                                                Instant.now()))
                .isInstanceOf(NetFlowV9DecodeException.class)
                .hasMessageContaining("Missing NetFlow v9 template");
    }

    static byte[] packetWithTemplateAndData() {
        ByteBuffer buffer =
                ByteBuffer.allocate(NetFlowV9Protocol.HEADER_LENGTH + templateFlowSetLength() + dataFlowSetLength())
                        .order(ByteOrder.BIG_ENDIAN);
        putHeader(buffer);
        putTemplateFlowSet(buffer);
        putDataFlowSet(buffer);
        return buffer.array();
    }

    static byte[] templateOnlyPacket() {
        ByteBuffer buffer =
                ByteBuffer.allocate(NetFlowV9Protocol.HEADER_LENGTH + templateFlowSetLength())
                        .order(ByteOrder.BIG_ENDIAN);
        putHeader(buffer);
        putTemplateFlowSet(buffer);
        return buffer.array();
    }

    static byte[] dataOnlyPacket() {
        ByteBuffer buffer =
                ByteBuffer.allocate(NetFlowV9Protocol.HEADER_LENGTH + dataFlowSetLength())
                        .order(ByteOrder.BIG_ENDIAN);
        putHeader(buffer);
        putDataFlowSet(buffer);
        return buffer.array();
    }

    private static void putHeader(ByteBuffer buffer) {
        buffer.putShort((short) 9);
        buffer.putShort((short) 1);
        buffer.putInt(1_000_000);
        buffer.putInt(1_700_000_000);
        buffer.putInt(100);
        buffer.putInt(123);
    }

    private static void putTemplateFlowSet(ByteBuffer buffer) {
        buffer.putShort((short) 0);
        buffer.putShort((short) templateFlowSetLength());
        buffer.putShort((short) 256);
        buffer.putShort((short) 10);
        putField(buffer, 8, 4);
        putField(buffer, 12, 4);
        putField(buffer, 7, 2);
        putField(buffer, 11, 2);
        putField(buffer, 4, 1);
        putField(buffer, 6, 1);
        putField(buffer, 1, 4);
        putField(buffer, 2, 4);
        putField(buffer, 22, 4);
        putField(buffer, 21, 4);
    }

    private static void putDataFlowSet(ByteBuffer buffer) {
        buffer.putShort((short) 256);
        buffer.putShort((short) dataFlowSetLength());
        buffer.putInt(ip(10, 0, 0, 3));
        buffer.putInt(ip(198, 51, 100, 9));
        buffer.putShort((short) 12_345);
        buffer.putShort((short) 443);
        buffer.put((byte) 6);
        buffer.put((byte) 19);
        buffer.putInt(9_876);
        buffer.putInt(10);
        buffer.putInt(999_000);
        buffer.putInt(999_800);
        buffer.putShort((short) 0);
    }

    private static void putField(ByteBuffer buffer, int type, int length) {
        buffer.putShort((short) type);
        buffer.putShort((short) length);
    }

    private static int templateFlowSetLength() {
        return 4 + 4 + (10 * 4);
    }

    private static int dataFlowSetLength() {
        return 4 + 30 + 2;
    }

    private static int ip(int a, int b, int c, int d) {
        return (a << 24) | (b << 16) | (c << 8) | d;
    }
}
