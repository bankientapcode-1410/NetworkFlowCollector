package com.kien.networkflowcollector.plugins.rest;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

public final class RestFlowNormalizerSupport {

    private RestFlowNormalizerSupport() {}

    public static NormalizedFlow normalizeRecord(RawFlowRecord raw) {
        Objects.requireNonNull(raw, "raw");
        if (!RestProtocol.SOURCE_TYPE.equals(raw.sourceType())) {
            throw new IllegalArgumentException("Unsupported source type: " + raw.sourceType());
        }

        Map<String, Object> fields = raw.fields();
        Instant tsStart = instantFieldOrDefault(fields, raw.receivedAt(), "ts_start", "start");
        Instant tsEnd = instantFieldOrDefault(fields, tsStart, "ts_end", "end");
        Object protocolValue = firstPresent(fields, "protocol", "proto", "protocol_number");
        String protocol = RestProtocol.protocolName(protocolValue);
        int protocolNumber = RestProtocol.protocolNumber(protocolValue);
        Long rawSamplingRate = nullableLongField(fields, "sampling_rate");
        Long samplePool = nullableLongField(fields, "sample_pool");
        boolean sampled =
                booleanFieldOrDefault(fields, "sampled", (rawSamplingRate != null && rawSamplingRate > 1) || samplePool != null);
        Long samplingRate = sampled ? rawSamplingRate : null;

        return new NormalizedFlow(
                flowId(raw, fields),
                tsStart,
                tsEnd,
                RestProtocol.durationMillis(tsStart, tsEnd),
                stringFieldOrDefault(fields, "src_ip", "0.0.0.0"),
                intFieldOrDefault(fields, "src_port", 0),
                stringFieldOrDefault(fields, "dst_ip", "0.0.0.0"),
                intFieldOrDefault(fields, "dst_port", 0),
                protocol,
                longFieldOrDefault(fields, 0, "bytes", "bytes_total"),
                longFieldOrDefault(fields, 0, "packets", "packets_total"),
                protocolNumber == 6 ? nullableIntField(fields, "tcp_flags") : null,
                sampled,
                samplingRate,
                samplePool,
                raw.sourceType(),
                raw.exporterIp(),
                null,
                nullableLongField(fields, "src_as", "src_asn"),
                null,
                null,
                nullableLongField(fields, "dst_as", "dst_asn"),
                null,
                raw.receivedAt());
    }

    private static UUID flowId(RawFlowRecord raw, Map<String, Object> fields) {
        String material =
                raw.sourceType()
                        + "|"
                        + raw.exporterIp()
                        + "|"
                        + optionalField(fields, "event_id", "client_event_id", "flow_id")
                        + "|"
                        + optionalField(fields, "ts_start", "start")
                        + "|"
                        + optionalField(fields, "ts_end", "end")
                        + "|"
                        + optionalField(fields, "src_ip")
                        + "|"
                        + optionalField(fields, "src_port")
                        + "|"
                        + optionalField(fields, "dst_ip")
                        + "|"
                        + optionalField(fields, "dst_port")
                        + "|"
                        + optionalField(fields, "protocol", "proto", "protocol_number")
                        + "|"
                        + optionalField(fields, "bytes", "bytes_total")
                        + "|"
                        + optionalField(fields, "packets", "packets_total");
        return UUID.nameUUIDFromBytes(material.getBytes(StandardCharsets.UTF_8));
    }

    private static Object firstPresent(Map<String, Object> fields, String... keys) {
        for (String key : keys) {
            Object value = fields.get(key);
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private static String optionalField(Map<String, Object> fields, String... keys) {
        Object value = firstPresent(fields, keys);
        return value == null ? "" : value.toString();
    }

    private static String stringFieldOrDefault(Map<String, Object> fields, String key, String defaultValue) {
        Object value = fields.get(key);
        return value == null ? defaultValue : value.toString();
    }

    private static int intFieldOrDefault(Map<String, Object> fields, String key, int defaultValue) {
        Object value = fields.get(key);
        return value == null ? defaultValue : RestProtocol.intValue(value);
    }

    private static long longFieldOrDefault(Map<String, Object> fields, long defaultValue, String... keys) {
        Object value = firstPresent(fields, keys);
        return value == null ? defaultValue : RestProtocol.longValue(value);
    }

    private static Long nullableLongField(Map<String, Object> fields, String... keys) {
        Object value = firstPresent(fields, keys);
        return value == null ? null : RestProtocol.longValue(value);
    }

    private static Integer nullableIntField(Map<String, Object> fields, String key) {
        Object value = fields.get(key);
        if (value == null) {
            return null;
        }
        if (value instanceof Number number) {
            return number.intValue();
        }
        String text = value.toString();
        try {
            return Integer.decode(text);
        } catch (NumberFormatException ignored) {
            return Integer.parseUnsignedInt(text, 16);
        }
    }

    private static Instant instantFieldOrDefault(Map<String, Object> fields, Instant defaultValue, String... keys) {
        Object value = firstPresent(fields, keys);
        return value == null ? defaultValue : RestProtocol.timestamp(value);
    }

    private static boolean booleanFieldOrDefault(Map<String, Object> fields, String key, boolean defaultValue) {
        Object value = fields.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Boolean bool) {
            return bool;
        }
        return Boolean.parseBoolean(value.toString());
    }
}
