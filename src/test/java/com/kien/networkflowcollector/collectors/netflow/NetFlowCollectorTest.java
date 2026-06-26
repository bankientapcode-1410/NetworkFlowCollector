package com.kien.networkflowcollector.collectors.netflow;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.kien.networkflowcollector.spi.RawFlowRecord;
import io.netty.buffer.Unpooled;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

class NetFlowCollectorTest {

    private final NetFlowCollector collector = new NetFlowCollector();

    @Test
    void dispatchesNetFlowV5Packets() {
        Instant receivedAt = Instant.parse("2026-06-24T12:00:00Z");

        List<RawFlowRecord> records =
                collector.decode(Unpooled.wrappedBuffer(netflowV5Packet()), "198.51.100.7", 55_000, receivedAt);

        assertThat(records).hasSize(1);
        assertThat(records.getFirst().sourceType()).isEqualTo("netflow-v5");
        assertThat(records.getFirst().exporterIp()).isEqualTo("198.51.100.7");
        assertThat(records.getFirst().receivedAt()).isEqualTo(receivedAt);
    }

    @Test
    void dispatchesNetFlowV9Packets() {
        List<RawFlowRecord> records =
                collector.decode(
                        Unpooled.wrappedBuffer(netflowV9TemplatePacket()),
                        "198.51.100.7",
                        55_000,
                        Instant.parse("2026-06-24T12:00:00Z"));

        assertThat(records).isEmpty();
    }

    @Test
    void rejectsUnsupportedNetFlowVersion() {
        byte[] packet = ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN).putShort((short) 7).array();

        assertThatThrownBy(
                        () ->
                                collector.decode(
                                        Unpooled.wrappedBuffer(packet),
                                        "198.51.100.7",
                                        55_000,
                                        Instant.now()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported NetFlow version: 7");
    }

    private static byte[] netflowV5Packet() {
        ByteBuffer buffer = ByteBuffer.allocate(24 + 48).order(ByteOrder.BIG_ENDIAN);
        buffer.putShort((short) 5);
        buffer.putShort((short) 1);
        buffer.putInt(1_000_000);
        buffer.putInt(1_700_000_000);
        buffer.putInt(0);
        buffer.putInt(1);
        buffer.put((byte) 0);
        buffer.put((byte) 0);
        buffer.putShort((short) 0);
        buffer.put(new byte[48]);
        return buffer.array();
    }

    private static byte[] netflowV9TemplatePacket() {
        ByteBuffer buffer = ByteBuffer.allocate(20 + 12).order(ByteOrder.BIG_ENDIAN);
        buffer.putShort((short) 9);
        buffer.putShort((short) 1);
        buffer.putInt(1_000_000);
        buffer.putInt(1_700_000_000);
        buffer.putInt(1);
        buffer.putInt(123);
        buffer.putShort((short) 0);
        buffer.putShort((short) 12);
        buffer.putShort((short) 256);
        buffer.putShort((short) 1);
        buffer.putShort((short) 8);
        buffer.putShort((short) 4);
        return buffer.array();
    }
}
