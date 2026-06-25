package com.kien.networkflowcollector.collectors.netflow.ipfix;

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

class IpfixDecoderTest {

    private final IpfixDecoder decoder = new IpfixDecoder();

    @Test
    void decodeTemplateAndDataSetsReturnsRawRecords() {
        Instant receivedAt = Instant.parse("2026-06-24T12:00:00Z");

        List<RawFlowRecord> records =
                decoder.decode(Unpooled.wrappedBuffer(messageWithTemplateAndData()), "198.51.100.7", receivedAt);

        assertThat(records).hasSize(1);
        RawFlowRecord record = records.getFirst();
        assertThat(record.sourceType()).isEqualTo("ipfix");
        assertThat(record.exporterIp()).isEqualTo("198.51.100.7");
        assertThat(record.receivedAt()).isEqualTo(receivedAt);

        Map<String, Object> fields = record.fields();
        assertThat(fields)
                .containsEntry("version", 10)
                .containsEntry("message_length", messageWithTemplateAndData().length)
                .containsEntry("record_index", 0)
                .containsEntry("sequence_number", 77L)
                .containsEntry("observation_domain_id", 12_345L)
                .containsEntry("template_id", 256)
                .containsEntry("src_ip", "192.0.2.20")
                .containsEntry("dst_ip", "203.0.113.30")
                .containsEntry("src_port", 53)
                .containsEntry("dst_port", 5_353)
                .containsEntry("protocol_number", 17)
                .containsEntry("protocol", "udp")
                .containsEntry("tcp_flags", 0)
                .containsEntry("bytes", 123_456_789L)
                .containsEntry("packets", 42L)
                .containsEntry("ts_start", Instant.parse("2023-11-14T22:13:20.123Z"))
                .containsEntry("ts_end", Instant.parse("2023-11-14T22:13:20.923Z"))
                .containsEntry("duration_ms", 800L);
    }

    @Test
    void supportsVariableLengthEnterpriseFields() {
        Instant receivedAt = Instant.parse("2026-06-24T12:00:00Z");

        List<RawFlowRecord> records =
                decoder.decode(Unpooled.wrappedBuffer(variableLengthEnterpriseMessage()), "198.51.100.7", receivedAt);

        assertThat(records).hasSize(1);
        assertThat(records.getFirst().fields())
                .containsEntry("src_ip", "10.10.10.1")
                .containsEntry("dst_ip", "10.10.10.2")
                .containsEntry("enterprise_32473_field_400", 0x616263L);
    }

    @Test
    void rejectsDataWithoutTemplate() {
        assertThatThrownBy(
                        () ->
                                new IpfixDecoder()
                                        .decode(
                                                Unpooled.wrappedBuffer(dataOnlyMessage()),
                                                "198.51.100.7",
                                                Instant.now()))
                .isInstanceOf(IpfixDecodeException.class)
                .hasMessageContaining("Missing IPFIX template");
    }

    static byte[] messageWithTemplateAndData() {
        int length = IpfixProtocol.HEADER_LENGTH + templateSetLength() + dataSetLength();
        ByteBuffer buffer = ByteBuffer.allocate(length).order(ByteOrder.BIG_ENDIAN);
        putHeader(buffer, length);
        putTemplateSet(buffer);
        putDataSet(buffer);
        return buffer.array();
    }

    static byte[] dataOnlyMessage() {
        int length = IpfixProtocol.HEADER_LENGTH + dataSetLength();
        ByteBuffer buffer = ByteBuffer.allocate(length).order(ByteOrder.BIG_ENDIAN);
        putHeader(buffer, length);
        putDataSet(buffer);
        return buffer.array();
    }

    private static byte[] variableLengthEnterpriseMessage() {
        int templateLength = 4 + 4 + 4 + 8 + 4 + 4 + 4 + 4;
        int dataLength = 4 + 4 + 1 + 3 + 4 + 4 + 4 + 4;
        int length = IpfixProtocol.HEADER_LENGTH + templateLength + dataLength;
        ByteBuffer buffer = ByteBuffer.allocate(length).order(ByteOrder.BIG_ENDIAN);
        putHeader(buffer, length);

        buffer.putShort((short) 2);
        buffer.putShort((short) templateLength);
        buffer.putShort((short) 300);
        buffer.putShort((short) 6);
        putField(buffer, 8, 4);
        buffer.putShort((short) (0x8000 | 400));
        buffer.putShort((short) 0xffff);
        buffer.putInt(32_473);
        putField(buffer, 12, 4);
        putField(buffer, 1, 4);
        putField(buffer, 2, 4);
        putField(buffer, 150, 4);

        buffer.putShort((short) 300);
        buffer.putShort((short) dataLength);
        buffer.putInt(ip(10, 10, 10, 1));
        buffer.put((byte) 3);
        buffer.put(new byte[] {'a', 'b', 'c'});
        buffer.putInt(ip(10, 10, 10, 2));
        buffer.putInt(100);
        buffer.putInt(2);
        buffer.putInt(1_700_000_000);
        return buffer.array();
    }

    private static void putHeader(ByteBuffer buffer, int length) {
        buffer.putShort((short) 10);
        buffer.putShort((short) length);
        buffer.putInt(1_700_000_000);
        buffer.putInt(77);
        buffer.putInt(12_345);
    }

    private static void putTemplateSet(ByteBuffer buffer) {
        buffer.putShort((short) 2);
        buffer.putShort((short) templateSetLength());
        buffer.putShort((short) 256);
        buffer.putShort((short) 10);
        putField(buffer, 8, 4);
        putField(buffer, 12, 4);
        putField(buffer, 7, 2);
        putField(buffer, 11, 2);
        putField(buffer, 4, 1);
        putField(buffer, 6, 2);
        putField(buffer, 1, 8);
        putField(buffer, 2, 8);
        putField(buffer, 152, 8);
        putField(buffer, 153, 8);
    }

    private static void putDataSet(ByteBuffer buffer) {
        buffer.putShort((short) 256);
        buffer.putShort((short) dataSetLength());
        buffer.putInt(ip(192, 0, 2, 20));
        buffer.putInt(ip(203, 0, 113, 30));
        buffer.putShort((short) 53);
        buffer.putShort((short) 5_353);
        buffer.put((byte) 17);
        buffer.putShort((short) 0);
        buffer.putLong(123_456_789L);
        buffer.putLong(42L);
        buffer.putLong(1_700_000_000_123L);
        buffer.putLong(1_700_000_000_923L);
        buffer.put((byte) 0);
    }

    private static void putField(ByteBuffer buffer, int type, int length) {
        buffer.putShort((short) type);
        buffer.putShort((short) length);
    }

    private static int templateSetLength() {
        return 4 + 4 + (10 * 4);
    }

    private static int dataSetLength() {
        return 4 + 47 + 1;
    }

    private static int ip(int a, int b, int c, int d) {
        return (a << 24) | (b << 16) | (c << 8) | d;
    }
}
