package com.kien.networkflowcollector.plugins.netflow.v5;

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

class NetFlowV5DecoderTest {

    private final NetFlowV5Decoder decoder = new NetFlowV5Decoder();

    @Test
    void decodeValidPacketReturnsRawRecords() {
        Instant receivedAt = Instant.parse("2026-06-24T12:00:00Z");

        List<RawFlowRecord> records =
                decoder.decode(Unpooled.wrappedBuffer(packet()), "198.51.100.7", receivedAt);

        assertThat(records).hasSize(2);
        RawFlowRecord first = records.getFirst();
        assertThat(first.sourceType()).isEqualTo("netflow-v5");
        assertThat(first.exporterIp()).isEqualTo("198.51.100.7");
        assertThat(first.receivedAt()).isEqualTo(receivedAt);

        Map<String, Object> fields = first.fields();
        assertThat(fields)
                .containsEntry("version", 5)
                .containsEntry("packet_record_count", 2)
                .containsEntry("record_index", 0)
                .containsEntry("sys_uptime_ms", 1_000_000L)
                .containsEntry("flow_sequence", 42L)
                .containsEntry("engine_type", 1)
                .containsEntry("engine_id", 2)
                .containsEntry("sampling_mode", 1)
                .containsEntry("sampling_interval", 100)
                .containsEntry("src_ip", "10.0.0.1")
                .containsEntry("dst_ip", "192.0.2.10")
                .containsEntry("next_hop", "0.0.0.0")
                .containsEntry("input_snmp", 3)
                .containsEntry("output_snmp", 4)
                .containsEntry("packets", 12L)
                .containsEntry("bytes", 3_456L)
                .containsEntry("first_switched_ms", 999_000L)
                .containsEntry("last_switched_ms", 999_500L)
                .containsEntry("ts_start", Instant.parse("2023-11-14T22:13:19.123Z"))
                .containsEntry("ts_end", Instant.parse("2023-11-14T22:13:19.623Z"))
                .containsEntry("duration_ms", 500L)
                .containsEntry("src_port", 54_321)
                .containsEntry("dst_port", 443)
                .containsEntry("tcp_flags", 27)
                .containsEntry("protocol_number", 6)
                .containsEntry("protocol", "tcp")
                .containsEntry("tos", 0)
                .containsEntry("src_as", 64_512)
                .containsEntry("dst_as", 64_513)
                .containsEntry("src_mask", 24)
                .containsEntry("dst_mask", 24);

        assertThat(records.get(1).fields())
                .containsEntry("record_index", 1)
                .containsEntry("src_ip", "10.0.0.2")
                .containsEntry("dst_ip", "203.0.113.10")
                .containsEntry("protocol_number", 17)
                .containsEntry("protocol", "udp");
    }

    @Test
    void rejectsUnsupportedVersion() {
        byte[] packet = packet();
        packet[1] = 9;

        assertThatThrownBy(
                        () ->
                                decoder.decode(
                                        Unpooled.wrappedBuffer(packet),
                                        "198.51.100.7",
                                        Instant.now()))
                .isInstanceOf(NetFlowV5DecodeException.class)
                .hasMessageContaining("Unsupported NetFlow version");
    }

    @Test
    void rejectsTruncatedPacket() {
        byte[] packet = ByteBuffer.allocate(24).putShort((short) 5).putShort((short) 1).array();

        assertThatThrownBy(
                        () ->
                                decoder.decode(
                                        Unpooled.wrappedBuffer(packet),
                                        "198.51.100.7",
                                        Instant.now()))
                .isInstanceOf(NetFlowV5DecodeException.class)
                .hasMessageContaining("truncated");
    }

    static byte[] packet() {
        ByteBuffer buffer =
                ByteBuffer.allocate(NetFlowV5Protocol.HEADER_LENGTH + (2 * NetFlowV5Protocol.RECORD_LENGTH))
                        .order(ByteOrder.BIG_ENDIAN);
        buffer.putShort((short) 5);
        buffer.putShort((short) 2);
        buffer.putInt(1_000_000);
        buffer.putInt(1_700_000_000);
        buffer.putInt(123_000_000);
        buffer.putInt(42);
        buffer.put((byte) 1);
        buffer.put((byte) 2);
        buffer.putShort((short) ((1 << 14) | 100));

        putRecord(
                buffer,
                ip(10, 0, 0, 1),
                ip(192, 0, 2, 10),
                ip(0, 0, 0, 0),
                3,
                4,
                12,
                3_456,
                999_000,
                999_500,
                54_321,
                443,
                27,
                6,
                0,
                64_512,
                64_513,
                24,
                24);
        putRecord(
                buffer,
                ip(10, 0, 0, 2),
                ip(203, 0, 113, 10),
                ip(0, 0, 0, 0),
                5,
                6,
                7,
                890,
                998_000,
                998_300,
                12_345,
                53,
                0,
                17,
                0,
                64_512,
                64_514,
                24,
                24);
        return buffer.array();
    }

    private static void putRecord(
            ByteBuffer buffer,
            int srcIp,
            int dstIp,
            int nextHop,
            int inputSnmp,
            int outputSnmp,
            long packets,
            long bytes,
            long firstSwitched,
            long lastSwitched,
            int srcPort,
            int dstPort,
            int tcpFlags,
            int protocol,
            int tos,
            int srcAs,
            int dstAs,
            int srcMask,
            int dstMask) {
        buffer.putInt(srcIp);
        buffer.putInt(dstIp);
        buffer.putInt(nextHop);
        buffer.putShort((short) inputSnmp);
        buffer.putShort((short) outputSnmp);
        buffer.putInt((int) packets);
        buffer.putInt((int) bytes);
        buffer.putInt((int) firstSwitched);
        buffer.putInt((int) lastSwitched);
        buffer.putShort((short) srcPort);
        buffer.putShort((short) dstPort);
        buffer.put((byte) 0);
        buffer.put((byte) tcpFlags);
        buffer.put((byte) protocol);
        buffer.put((byte) tos);
        buffer.putShort((short) srcAs);
        buffer.putShort((short) dstAs);
        buffer.put((byte) srcMask);
        buffer.put((byte) dstMask);
        buffer.putShort((short) 0);
    }

    private static int ip(int a, int b, int c, int d) {
        return (a << 24) | (b << 16) | (c << 8) | d;
    }
}
