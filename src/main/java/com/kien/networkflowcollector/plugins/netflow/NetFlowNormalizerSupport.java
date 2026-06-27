package com.kien.networkflowcollector.plugins.netflow;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

public final class NetFlowNormalizerSupport {

    private NetFlowNormalizerSupport() {}

    public static NormalizedFlow normalizeFixedRecord(RawFlowRecord raw, String expectedSourceType, String missingFieldSourceName) {
        Objects.requireNonNull(raw, "raw");
        Objects.requireNonNull(missingFieldSourceName, "missingFieldSourceName");
        if (!expectedSourceType.equals(raw.sourceType())) {
            throw new IllegalArgumentException("Unsupported source type: " + raw.sourceType());
        }

        Map<String, Object> fields = raw.fields();
        Instant tsStart = requiredInstantField(fields, "ts_start", missingFieldSourceName);
        Instant tsEnd = requiredInstantField(fields, "ts_end", missingFieldSourceName);
        int protocolNumber = requiredIntField(fields, "protocol_number", missingFieldSourceName);
        int samplingMode = requiredIntField(fields, "sampling_mode", missingFieldSourceName);
        int samplingInterval = requiredIntField(fields, "sampling_interval", missingFieldSourceName);
        boolean sampled = samplingMode != 0 || samplingInterval > 1;
        Long samplingRate = sampled ? (long) samplingInterval : null;

        return new NormalizedFlow(
                fixedRecordFlowId(raw, fields, missingFieldSourceName),
                tsStart,
                tsEnd,
                requiredLongField(fields, "duration_ms", missingFieldSourceName),
                requiredStringField(fields, "src_ip", missingFieldSourceName),
                requiredIntField(fields, "src_port", missingFieldSourceName),
                requiredStringField(fields, "dst_ip", missingFieldSourceName),
                requiredIntField(fields, "dst_port", missingFieldSourceName),
                requiredStringField(fields, "protocol", missingFieldSourceName),
                requiredLongField(fields, "bytes", missingFieldSourceName),
                requiredLongField(fields, "packets", missingFieldSourceName),
                protocolNumber == 6
                        ? requiredIntField(fields, "tcp_flags", missingFieldSourceName)
                        : null,
                sampled,
                samplingRate,
                null,
                raw.sourceType(),
                raw.exporterIp(),
                null,
                null,
                null,
                null,
                null,
                null,
                raw.receivedAt());
    }

    public static NormalizedFlow normalizeFlexibleRecord(RawFlowRecord raw, String expectedSourceType) {
        Objects.requireNonNull(raw, "raw");
        if (!expectedSourceType.equals(raw.sourceType())) {
            throw new IllegalArgumentException("Unsupported source type: " + raw.sourceType());
        }

        Map<String, Object> fields = raw.fields();
        Instant exportTime = instantFieldOrDefault(fields, "export_time", raw.receivedAt());
        Instant tsStart = instantFieldOrDefault(fields, "ts_start", exportTime);
        Instant tsEnd = instantFieldOrDefault(fields, "ts_end", tsStart);
        long durationMs =
                longFieldOrDefault(
                        fields,
                        "duration_ms",
                        NetFlowProtocolSupport.durationMillis(tsStart, tsEnd));
        int protocolNumber = intFieldOrDefault(fields, "protocol_number", 0);
        String protocol =
                stringFieldOrDefault(
                        fields,
                        "protocol",
                        NetFlowProtocolSupport.protocolName(protocolNumber));
        Long rawSamplingRate =
                nullableLongField(
                        fields.containsKey("sampling_rate") ? fields : fields,
                        fields.containsKey("sampling_rate") ? "sampling_rate" : "sampling_interval");
        Long samplePool = nullableLongField(fields, "sample_pool");
        boolean sampled =
                booleanFieldOrDefault(
                        fields,
                        "sampled",
                        (rawSamplingRate != null && rawSamplingRate > 1) || samplePool != null);
        Long samplingRate = sampled ? rawSamplingRate : null;

        return new NormalizedFlow(
                flowId(raw, fields),
                tsStart,
                tsEnd,
                durationMs,
                stringFieldOrDefault(fields, "src_ip", "0.0.0.0"),
                intFieldOrDefault(fields, "src_port", 0),
                stringFieldOrDefault(fields, "dst_ip", "0.0.0.0"),
                intFieldOrDefault(fields, "dst_port", 0),
                protocol,
                longFieldOrDefault(fields, "bytes", 0),
                longFieldOrDefault(fields, "packets", 0),
                protocolNumber == 6 ? nullableIntField(fields, "tcp_flags") : null,
                sampled,
                samplingRate,
                samplePool,
                raw.sourceType(),
                raw.exporterIp(),
                null,
                nullableLongField(fields, "src_as"),
                null,
                null,
                nullableLongField(fields, "dst_as"),
                null,
                raw.receivedAt());
    }

    private static UUID fixedRecordFlowId(RawFlowRecord raw, Map<String, Object> fields, String missingFieldSourceName) {
        String material =
                raw.sourceType()
                        + "|"
                        + raw.exporterIp()
                        + "|"
                        + requiredLongField(fields, "flow_sequence", missingFieldSourceName)
                        + "|"
                        + requiredIntField(fields, "record_index", missingFieldSourceName)
                        + "|"
                        + requiredInstantField(fields, "ts_start", missingFieldSourceName)
                        + "|"
                        + requiredInstantField(fields, "ts_end", missingFieldSourceName)
                        + "|"
                        + requiredStringField(fields, "src_ip", missingFieldSourceName)
                        + "|"
                        + requiredIntField(fields, "src_port", missingFieldSourceName)
                        + "|"
                        + requiredStringField(fields, "dst_ip", missingFieldSourceName)
                        + "|"
                        + requiredIntField(fields, "dst_port", missingFieldSourceName)
                        + "|"
                        + requiredIntField(fields, "protocol_number", missingFieldSourceName);
        return UUID.nameUUIDFromBytes(material.getBytes(StandardCharsets.UTF_8));
    }

    private static UUID flowId(RawFlowRecord raw, Map<String, Object> fields) {
        String material =
                raw.sourceType()
                        + "|"
                        + raw.exporterIp()
                        + "|"
                        + optionalField(fields, "source_id")
                        + "|"
                        + optionalField(fields, "observation_domain_id")
                        + "|"
                        + optionalField(fields, "flow_sequence")
                        + "|"
                        + optionalField(fields, "sequence_number")
                        + "|"
                        + optionalField(fields, "template_id")
                        + "|"
                        + optionalField(fields, "record_index")
                        + "|"
                        + optionalField(fields, "ts_start")
                        + "|"
                        + optionalField(fields, "ts_end")
                        + "|"
                        + optionalField(fields, "src_ip")
                        + "|"
                        + optionalField(fields, "src_port")
                        + "|"
                        + optionalField(fields, "dst_ip")
                        + "|"
                        + optionalField(fields, "dst_port")
                        + "|"
                        + optionalField(fields, "protocol_number");
        return UUID.nameUUIDFromBytes(material.getBytes(StandardCharsets.UTF_8));
    }

    private static String optionalField(Map<String, Object> fields, String key) {
        Object value = fields.get(key);
        return value == null ? "" : value.toString();
    }

    private static String requiredStringField(
            Map<String, Object> fields, String key, String missingFieldSourceName) {
        return requiredField(fields, key, missingFieldSourceName).toString();
    }

    private static int requiredIntField(
            Map<String, Object> fields, String key, String missingFieldSourceName) {
        Object value = requiredField(fields, key, missingFieldSourceName);
        if (value instanceof Number number) {
            return number.intValue();
        }
        return Integer.parseInt(value.toString());
    }

    private static long requiredLongField(
            Map<String, Object> fields, String key, String missingFieldSourceName) {
        Object value = requiredField(fields, key, missingFieldSourceName);
        if (value instanceof Number number) {
            return number.longValue();
        }
        return Long.parseLong(value.toString());
    }

    private static Instant requiredInstantField(
            Map<String, Object> fields, String key, String missingFieldSourceName) {
        Object value = requiredField(fields, key, missingFieldSourceName);
        if (value instanceof Instant instant) {
            return instant;
        }
        return Instant.parse(value.toString());
    }

    private static Object requiredField(
            Map<String, Object> fields, String key, String missingFieldSourceName) {
        Object value = fields.get(key);
        if (value == null) {
            throw new IllegalArgumentException("Missing " + missingFieldSourceName + " field: " + key);
        }
        return value;
    }

    private static String stringFieldOrDefault(Map<String, Object> fields, String key, String defaultValue) {
        Object value = fields.get(key);
        return value == null ? defaultValue : value.toString();
    }

    private static int intFieldOrDefault(Map<String, Object> fields, String key, int defaultValue) {
        Object value = fields.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Number number) {
            return number.intValue();
        }
        return Integer.parseInt(value.toString());
    }

    private static Integer nullableIntField(Map<String, Object> fields, String key) {
        Object value = fields.get(key);
        if (value == null) {
            return null;
        }
        if (value instanceof Number number) {
            return number.intValue();
        }
        return Integer.parseInt(value.toString());
    }

    private static long longFieldOrDefault(Map<String, Object> fields, String key, long defaultValue) {
        Object value = fields.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof BigInteger bigInteger) {
            return bigInteger.longValue();
        }
        if (value instanceof Number number) {
            return number.longValue();
        }
        return Long.parseLong(value.toString());
    }

    private static Long nullableLongField(Map<String, Object> fields, String key) {
        Object value = fields.get(key);
        if (value == null) {
            return null;
        }
        if (value instanceof BigInteger bigInteger) {
            return bigInteger.longValue();
        }
        if (value instanceof Number number) {
            return number.longValue();
        }
        return Long.parseLong(value.toString());
    }

    private static Instant instantFieldOrDefault(Map<String, Object> fields, String key, Instant defaultValue) {
        Object value = fields.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Instant instant) {
            return instant;
        }
        return Instant.parse(value.toString());
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
