package com.kien.networkflowcollector.plugins.suricata;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

public final class SuricataNormalizerSupport {

    private SuricataNormalizerSupport() {}

    public static NormalizedFlow normalizeFlowRecord(RawFlowRecord raw) {
        Objects.requireNonNull(raw, "raw");
        if (!SuricataProtocol.FLOW_SOURCE_TYPE.equals(raw.sourceType())) {
            throw new IllegalArgumentException("Unsupported source type: " + raw.sourceType());
        }

        Map<String, Object> fields = raw.fields();
        Instant tsStart = instantFieldOrDefault(fields, "ts_start", raw.receivedAt());
        Instant tsEnd = instantFieldOrDefault(fields, "ts_end", tsStart);
        long durationMs =
                longFieldOrDefault(
                        fields,
                        "duration_ms",
                        Math.max(Duration.between(tsStart, tsEnd).toMillis(), 0));
        String protocol = stringFieldOrDefault(fields, "protocol", "unknown");
        int protocolNumber =
                intFieldOrDefault(fields, "protocol_number", SuricataProtocol.protocolNumber(protocol));

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
                booleanFieldOrDefault(fields, "sampled", false),
                nullableLongField(fields, "sampling_rate"),
                nullableLongField(fields, "sample_pool"),
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

    private static UUID flowId(RawFlowRecord raw, Map<String, Object> fields) {
        String material =
                raw.sourceType()
                        + "|"
                        + raw.exporterIp()
                        + "|"
                        + optionalField(fields, "flow_id")
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
                        + optionalField(fields, "protocol");
        return UUID.nameUUIDFromBytes(material.getBytes(StandardCharsets.UTF_8));
    }

    private static String optionalField(Map<String, Object> fields, String key) {
        Object value = fields.get(key);
        return value == null ? "" : value.toString();
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

    private static Instant instantFieldOrDefault(Map<String, Object> fields, String key, Instant defaultValue) {
        Object value = fields.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Instant instant) {
            return instant;
        }
        return SuricataProtocol.timestamp(value);
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
