package com.kien.networkflowcollector.plugins.netflow.v5;

import com.kien.networkflowcollector.plugins.netflow.NetFlowProtocolSupport;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import io.netty.buffer.ByteBuf;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class NetFlowV5Decoder {

    public List<RawFlowRecord> decode(ByteBuf packet, String exporterIp, Instant receivedAt) {
        Objects.requireNonNull(packet, "packet");
        Objects.requireNonNull(exporterIp, "exporterIp");
        Objects.requireNonNull(receivedAt, "receivedAt");

        int base = packet.readerIndex();
        int length = packet.readableBytes();
        if (length < NetFlowV5Protocol.HEADER_LENGTH) {
            throw new NetFlowV5DecodeException("NetFlow v5 packet too short: " + length + " bytes");
        }

        int version = packet.getUnsignedShort(base);
        if (version != NetFlowV5Protocol.VERSION) {
            throw new NetFlowV5DecodeException("Unsupported NetFlow version: " + version);
        }

        int recordCount = packet.getUnsignedShort(base + 2);
        if (recordCount > NetFlowV5Protocol.MAX_RECORDS) {
            throw new NetFlowV5DecodeException("NetFlow v5 record count exceeds 30: " + recordCount);
        }

        int expectedLength =
                NetFlowV5Protocol.HEADER_LENGTH + (recordCount * NetFlowV5Protocol.RECORD_LENGTH);
        if (length < expectedLength) {
            throw new NetFlowV5DecodeException(
                    "NetFlow v5 packet truncated: expected at least "
                            + expectedLength
                            + " bytes but got "
                            + length);
        }

        long sysUptimeMillis = packet.getUnsignedInt(base + 4);
        long unixSeconds = packet.getUnsignedInt(base + 8);
        long unixNanos = packet.getUnsignedInt(base + 12);
        long flowSequence = packet.getUnsignedInt(base + 16);
        int engineType = packet.getUnsignedByte(base + 20);
        int engineId = packet.getUnsignedByte(base + 21);
        int sampling = packet.getUnsignedShort(base + 22);
        int samplingMode = sampling >>> 14;
        int samplingInterval = sampling & 0x3fff;
        Instant exportTime = NetFlowProtocolSupport.exportTime(unixSeconds, unixNanos);

        List<RawFlowRecord> out = new ArrayList<>(recordCount);
        for (int i = 0; i < recordCount; i++) {
            int offset =
                    base + NetFlowV5Protocol.HEADER_LENGTH + (i * NetFlowV5Protocol.RECORD_LENGTH);
            out.add(
                    new RawFlowRecord(
                            NetFlowV5Protocol.SOURCE_TYPE,
                            exporterIp,
                            receivedAt,
                            fieldsForRecord(
                                    packet,
                                    offset,
                                    i,
                                    recordCount,
                                    sysUptimeMillis,
                                    unixSeconds,
                                    unixNanos,
                                    flowSequence,
                                    engineType,
                                    engineId,
                                    samplingMode,
                                    samplingInterval,
                                    exportTime)));
        }
        return out;
    }

    private Map<String, Object> fieldsForRecord(
            ByteBuf packet,
            int offset,
            int recordIndex,
            int recordCount,
            long sysUptimeMillis,
            long unixSeconds,
            long unixNanos,
            long flowSequence,
            int engineType,
            int engineId,
            int samplingMode,
            int samplingInterval,
            Instant exportTime) {
        long firstSwitchedMillis = packet.getUnsignedInt(offset + 24);
        long lastSwitchedMillis = packet.getUnsignedInt(offset + 28);
        int protocolNumber = packet.getUnsignedByte(offset + 38);

        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("version", NetFlowV5Protocol.VERSION);
        fields.put("packet_record_count", recordCount);
        fields.put("record_index", recordIndex);
        fields.put("sys_uptime_ms", sysUptimeMillis);
        fields.put("unix_secs", unixSeconds);
        fields.put("unix_nsecs", unixNanos);
        fields.put("export_time", exportTime);
        fields.put("flow_sequence", flowSequence);
        fields.put("engine_type", engineType);
        fields.put("engine_id", engineId);
        fields.put("sampling_mode", samplingMode);
        fields.put("sampling_interval", samplingInterval);
        fields.put("src_ip", NetFlowProtocolSupport.ipv4(packet.getUnsignedInt(offset)));
        fields.put("dst_ip", NetFlowProtocolSupport.ipv4(packet.getUnsignedInt(offset + 4)));
        fields.put("next_hop", NetFlowProtocolSupport.ipv4(packet.getUnsignedInt(offset + 8)));
        fields.put("input_snmp", packet.getUnsignedShort(offset + 12));
        fields.put("output_snmp", packet.getUnsignedShort(offset + 14));
        fields.put("packets", packet.getUnsignedInt(offset + 16));
        fields.put("bytes", packet.getUnsignedInt(offset + 20));
        fields.put("first_switched_ms", firstSwitchedMillis);
        fields.put("last_switched_ms", lastSwitchedMillis);
        fields.put(
                "ts_start",
                NetFlowProtocolSupport.switchedTime(exportTime, sysUptimeMillis, firstSwitchedMillis));
        fields.put(
                "ts_end",
                NetFlowProtocolSupport.switchedTime(exportTime, sysUptimeMillis, lastSwitchedMillis));
        fields.put(
                "duration_ms",
                NetFlowProtocolSupport.durationMillis(firstSwitchedMillis, lastSwitchedMillis));
        fields.put("src_port", packet.getUnsignedShort(offset + 32));
        fields.put("dst_port", packet.getUnsignedShort(offset + 34));
        fields.put("tcp_flags", (int) packet.getUnsignedByte(offset + 37));
        fields.put("protocol_number", protocolNumber);
        fields.put("protocol", NetFlowProtocolSupport.protocolName(protocolNumber));
        fields.put("tos", (int) packet.getUnsignedByte(offset + 39));
        fields.put("src_as", packet.getUnsignedShort(offset + 40));
        fields.put("dst_as", packet.getUnsignedShort(offset + 42));
        fields.put("src_mask", (int) packet.getUnsignedByte(offset + 44));
        fields.put("dst_mask", (int) packet.getUnsignedByte(offset + 45));
        return fields;
    }
}
