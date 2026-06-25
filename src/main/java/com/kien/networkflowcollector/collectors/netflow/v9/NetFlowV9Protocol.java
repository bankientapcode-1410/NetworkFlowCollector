package com.kien.networkflowcollector.collectors.netflow.v9;

import com.kien.networkflowcollector.collectors.netflow.NetFlowProtocolSupport;
import com.kien.networkflowcollector.collectors.netflow.template.TemplateField;
import io.netty.buffer.ByteBuf;
import java.time.Instant;
import java.util.Map;

final class NetFlowV9Protocol {

    static final String SOURCE_TYPE = "netflow-v9";
    static final String TEMPLATE_PROTOCOL = "netflow-v9";
    static final int VERSION = 9;
    static final int HEADER_LENGTH = 20;
    static final int TEMPLATE_FLOWSET_ID = 0;
    static final int OPTIONS_TEMPLATE_FLOWSET_ID = 1;
    static final int MIN_DATA_FLOWSET_ID = 256;

    private NetFlowV9Protocol() {}

    static String exporterKey(String exporterIp, int exporterPort) {
        return exporterPort < 0 ? exporterIp : exporterIp + ":" + exporterPort;
    }

    static void putField(
            Map<String, Object> fields,
            TemplateField field,
            ByteBuf packet,
            int offset,
            Instant exportTime,
            long sysUptimeMillis) {
        int length = field.length();
        switch (field.type()) {
            case 1 -> putCounter(fields, "bytes", "in_bytes", unsigned(packet, offset, length));
            case 2 -> putCounter(fields, "packets", "in_packets", unsigned(packet, offset, length));
            case 4 -> putProtocol(fields, (int) unsigned(packet, offset, length));
            case 5 -> fields.put("tos", (int) unsigned(packet, offset, length));
            case 6 -> fields.put("tcp_flags", (int) unsigned(packet, offset, length));
            case 7 -> fields.put("src_port", (int) unsigned(packet, offset, length));
            case 8 -> fields.put("src_ip", NetFlowProtocolSupport.ipv4(packet, offset));
            case 9 -> fields.put("src_mask", (int) unsigned(packet, offset, length));
            case 10 -> fields.put("input_snmp", unsigned(packet, offset, length));
            case 11 -> fields.put("dst_port", (int) unsigned(packet, offset, length));
            case 12 -> fields.put("dst_ip", NetFlowProtocolSupport.ipv4(packet, offset));
            case 13 -> fields.put("dst_mask", (int) unsigned(packet, offset, length));
            case 14 -> fields.put("output_snmp", unsigned(packet, offset, length));
            case 15 -> fields.put("next_hop", NetFlowProtocolSupport.ipv4(packet, offset));
            case 16 -> fields.put("src_as", unsigned(packet, offset, length));
            case 17 -> fields.put("dst_as", unsigned(packet, offset, length));
            case 21 -> fields.put("last_switched_ms", unsigned(packet, offset, length));
            case 22 -> fields.put("first_switched_ms", unsigned(packet, offset, length));
            case 23 -> putCounter(fields, "bytes", "out_bytes", unsigned(packet, offset, length));
            case 24 -> putCounter(fields, "packets", "out_packets", unsigned(packet, offset, length));
            case 27 -> fields.put("src_ip", NetFlowProtocolSupport.ipv6(packet, offset));
            case 28 -> fields.put("dst_ip", NetFlowProtocolSupport.ipv6(packet, offset));
            case 29 -> fields.put("src_mask", (int) unsigned(packet, offset, length));
            case 30 -> fields.put("dst_mask", (int) unsigned(packet, offset, length));
            case 34 -> fields.put("sampling_interval", unsigned(packet, offset, length));
            case 35 -> fields.put("sampling_algorithm", (int) unsigned(packet, offset, length));
            case 38 -> fields.put("engine_type", (int) unsigned(packet, offset, length));
            case 39 -> fields.put("engine_id", (int) unsigned(packet, offset, length));
            default -> putUnknown(fields, field, packet, offset, length);
        }
    }

    static void finishRecord(Map<String, Object> fields, Instant exportTime, long sysUptimeMillis) {
        Long firstSwitchedMillis = numberField(fields, "first_switched_ms");
        Long lastSwitchedMillis = numberField(fields, "last_switched_ms");
        if (firstSwitchedMillis != null) {
            fields.put("ts_start", NetFlowProtocolSupport.switchedTime(exportTime, sysUptimeMillis, firstSwitchedMillis));
        }
        if (lastSwitchedMillis != null) {
            fields.put("ts_end", NetFlowProtocolSupport.switchedTime(exportTime, sysUptimeMillis, lastSwitchedMillis));
        }
        if (firstSwitchedMillis != null && lastSwitchedMillis != null) {
            fields.put("duration_ms", NetFlowProtocolSupport.durationMillis(firstSwitchedMillis, lastSwitchedMillis));
        } else if (fields.get("ts_start") instanceof Instant tsStart
                && fields.get("ts_end") instanceof Instant tsEnd) {
            fields.put("duration_ms", NetFlowProtocolSupport.durationMillis(tsStart, tsEnd));
        }

        Long samplingInterval = numberField(fields, "sampling_interval");
        if (samplingInterval != null && samplingInterval > 0) {
            fields.put("sampling_rate", samplingInterval);
            fields.put("sampled", samplingInterval > 1);
        }
    }

    private static void putProtocol(Map<String, Object> fields, int protocolNumber) {
        fields.put("protocol_number", protocolNumber);
        fields.put("protocol", NetFlowProtocolSupport.protocolName(protocolNumber));
    }

    private static void putCounter(Map<String, Object> fields, String canonicalKey, String sourceKey, long value) {
        fields.putIfAbsent(canonicalKey, value);
        NetFlowProtocolSupport.putUnique(fields, sourceKey, value);
    }

    private static void putUnknown(
            Map<String, Object> fields, TemplateField field, ByteBuf packet, int offset, int length) {
        Object value =
                length <= Long.BYTES
                        ? unsigned(packet, offset, length)
                        : NetFlowProtocolSupport.hex(packet, offset, length);
        NetFlowProtocolSupport.putUnique(fields, "netflow_v9_field_" + field.type(), value);
    }

    private static long unsigned(ByteBuf packet, int offset, int length) {
        return NetFlowProtocolSupport.unsignedNumber(packet, offset, length);
    }

    private static Long numberField(Map<String, Object> fields, String key) {
        Object value = fields.get(key);
        return value instanceof Number number ? number.longValue() : null;
    }
}
