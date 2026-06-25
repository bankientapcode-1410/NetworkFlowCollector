package com.kien.networkflowcollector.collectors.netflow.ipfix;

import com.kien.networkflowcollector.collectors.netflow.NetFlowProtocolSupport;
import com.kien.networkflowcollector.collectors.netflow.template.TemplateField;
import io.netty.buffer.ByteBuf;
import java.time.Instant;
import java.util.Map;

final class IpfixProtocol {

    static final String SOURCE_TYPE = "ipfix";
    static final String TEMPLATE_PROTOCOL = "ipfix";
    static final int VERSION = 10;
    static final int HEADER_LENGTH = 16;
    static final int TEMPLATE_SET_ID = 2;
    static final int OPTIONS_TEMPLATE_SET_ID = 3;
    static final int MIN_DATA_SET_ID = 256;

    private IpfixProtocol() {}

    static String exporterKey(String exporterIp, int exporterPort) {
        return exporterPort < 0 ? exporterIp : exporterIp + ":" + exporterPort;
    }

    static void putField(
            Map<String, Object> fields,
            TemplateField field,
            ByteBuf packet,
            int offset,
            int length,
            Instant exportTime) {
        if (field.enterpriseSpecific()) {
            putEnterpriseField(fields, field, packet, offset, length);
            return;
        }

        switch (field.type()) {
            case 1 -> putCounter(fields, "bytes", "octet_delta_count", unsigned(packet, offset, length));
            case 2 -> putCounter(fields, "packets", "packet_delta_count", unsigned(packet, offset, length));
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
            case 21 -> fields.put("flow_end_sys_up_time_ms", unsigned(packet, offset, length));
            case 22 -> fields.put("flow_start_sys_up_time_ms", unsigned(packet, offset, length));
            case 27 -> fields.put("src_ip", NetFlowProtocolSupport.ipv6(packet, offset));
            case 28 -> fields.put("dst_ip", NetFlowProtocolSupport.ipv6(packet, offset));
            case 29 -> fields.put("src_mask", (int) unsigned(packet, offset, length));
            case 30 -> fields.put("dst_mask", (int) unsigned(packet, offset, length));
            case 34 -> fields.put("sampling_interval", unsigned(packet, offset, length));
            case 35 -> fields.put("sampling_algorithm", (int) unsigned(packet, offset, length));
            case 85 -> putCounter(fields, "bytes", "octet_total_count", unsigned(packet, offset, length));
            case 86 -> putCounter(fields, "packets", "packet_total_count", unsigned(packet, offset, length));
            case 150 -> fields.put("ts_start", NetFlowProtocolSupport.exportTimeSeconds(unsigned(packet, offset, length)));
            case 151 -> fields.put("ts_end", NetFlowProtocolSupport.exportTimeSeconds(unsigned(packet, offset, length)));
            case 152 -> fields.put("ts_start", NetFlowProtocolSupport.epochMilliseconds(unsigned(packet, offset, length)));
            case 153 -> fields.put("ts_end", NetFlowProtocolSupport.epochMilliseconds(unsigned(packet, offset, length)));
            case 154, 156 -> fields.put("ts_start", ntpTimestamp(packet, offset, length));
            case 155, 157 -> fields.put("ts_end", ntpTimestamp(packet, offset, length));
            case 158 -> {
                long micros = unsigned(packet, offset, length);
                fields.put("flow_start_delta_microseconds", micros);
                fields.put("ts_start", exportTime.minusNanos(micros * 1_000L));
            }
            case 159 -> {
                long micros = unsigned(packet, offset, length);
                fields.put("flow_end_delta_microseconds", micros);
                fields.put("ts_end", exportTime.minusNanos(micros * 1_000L));
            }
            case 160 -> fields.put("system_init_time", NetFlowProtocolSupport.epochMilliseconds(unsigned(packet, offset, length)));
            case 161 -> fields.put("duration_ms", unsigned(packet, offset, length));
            case 162 -> fields.put("duration_ms", unsigned(packet, offset, length) / 1_000L);
            default -> putUnknown(fields, field, packet, offset, length);
        }
    }

    static void finishRecord(Map<String, Object> fields, Instant exportTime) {
        Object systemInitValue = fields.get("system_init_time");
        Instant systemInit = systemInitValue instanceof Instant instant ? instant : null;
        if (systemInit != null && !fields.containsKey("ts_start")) {
            Long startSysUpTime = numberField(fields, "flow_start_sys_up_time_ms");
            if (startSysUpTime != null) {
                fields.put("ts_start", systemInit.plusMillis(startSysUpTime));
            }
        }
        if (systemInit != null && !fields.containsKey("ts_end")) {
            Long endSysUpTime = numberField(fields, "flow_end_sys_up_time_ms");
            if (endSysUpTime != null) {
                fields.put("ts_end", systemInit.plusMillis(endSysUpTime));
            }
        }

        Instant tsStart = fields.get("ts_start") instanceof Instant instant ? instant : null;
        Instant tsEnd = fields.get("ts_end") instanceof Instant instant ? instant : null;
        Long durationMs = numberField(fields, "duration_ms");
        if (tsStart != null && tsEnd != null && durationMs == null) {
            fields.put("duration_ms", NetFlowProtocolSupport.durationMillis(tsStart, tsEnd));
        } else if (tsStart != null && tsEnd == null && durationMs != null) {
            fields.put("ts_end", tsStart.plusMillis(durationMs));
        } else if (tsEnd != null && tsStart == null && durationMs != null) {
            fields.put("ts_start", tsEnd.minusMillis(durationMs));
        } else if (tsStart == null && tsEnd == null) {
            fields.put("ts_start", exportTime);
            fields.put("ts_end", exportTime);
            fields.putIfAbsent("duration_ms", 0L);
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

    private static void putEnterpriseField(
            Map<String, Object> fields, TemplateField field, ByteBuf packet, int offset, int length) {
        Object value =
                length <= Long.BYTES
                        ? unsigned(packet, offset, length)
                        : NetFlowProtocolSupport.hex(packet, offset, length);
        NetFlowProtocolSupport.putUnique(
                fields,
                "enterprise_" + field.enterpriseNumber() + "_field_" + field.type(),
                value);
    }

    private static void putUnknown(
            Map<String, Object> fields, TemplateField field, ByteBuf packet, int offset, int length) {
        Object value =
                length <= Long.BYTES
                        ? unsigned(packet, offset, length)
                        : NetFlowProtocolSupport.hex(packet, offset, length);
        NetFlowProtocolSupport.putUnique(fields, "ipfix_ie_" + field.type(), value);
    }

    private static Instant ntpTimestamp(ByteBuf packet, int offset, int length) {
        if (length != Long.BYTES) {
            throw new IpfixDecodeException("IPFIX NTP timestamp must be 8 bytes but was " + length);
        }
        return NetFlowProtocolSupport.ntpTimestamp(
                packet.getUnsignedInt(offset), packet.getUnsignedInt(offset + 4));
    }

    private static long unsigned(ByteBuf packet, int offset, int length) {
        return NetFlowProtocolSupport.unsignedNumber(packet, offset, length);
    }

    private static Long numberField(Map<String, Object> fields, String key) {
        Object value = fields.get(key);
        return value instanceof Number number ? number.longValue() : null;
    }
}
