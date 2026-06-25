package com.kien.networkflowcollector.collectors.netflow.v5;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.spi.FlowNormalizer;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import org.springframework.stereotype.Component;

@Component
public class NetFlowV5Normalizer implements FlowNormalizer {

    @Override
    public String sourceType() {
        return NetFlowV5Protocol.SOURCE_TYPE;
    }

    @Override
    public NormalizedFlow normalize(RawFlowRecord raw) {
        Objects.requireNonNull(raw, "raw");
        if (!NetFlowV5Protocol.SOURCE_TYPE.equals(raw.sourceType())) {
            throw new IllegalArgumentException("Unsupported source type: " + raw.sourceType());
        }

        Map<String, Object> fields = raw.fields();
        Instant tsStart = instantField(fields, "ts_start");
        Instant tsEnd = instantField(fields, "ts_end");
        int protocolNumber = intField(fields, "protocol_number");
        int samplingMode = intField(fields, "sampling_mode");
        int samplingInterval = intField(fields, "sampling_interval");
        Long samplingRate = samplingInterval > 0 ? (long) samplingInterval : null;

        return new NormalizedFlow(
                flowId(raw, fields),
                tsStart,
                tsEnd,
                longField(fields, "duration_ms"),
                stringField(fields, "src_ip"),
                intField(fields, "src_port"),
                stringField(fields, "dst_ip"),
                intField(fields, "dst_port"),
                stringField(fields, "protocol"),
                longField(fields, "bytes"),
                longField(fields, "packets"),
                protocolNumber == 6 ? intField(fields, "tcp_flags") : null,
                samplingMode != 0 || samplingInterval > 1,
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

    private static UUID flowId(RawFlowRecord raw, Map<String, Object> fields) {
        String material =
                raw.sourceType()
                        + "|"
                        + raw.exporterIp()
                        + "|"
                        + longField(fields, "flow_sequence")
                        + "|"
                        + intField(fields, "record_index")
                        + "|"
                        + instantField(fields, "ts_start")
                        + "|"
                        + instantField(fields, "ts_end")
                        + "|"
                        + stringField(fields, "src_ip")
                        + "|"
                        + intField(fields, "src_port")
                        + "|"
                        + stringField(fields, "dst_ip")
                        + "|"
                        + intField(fields, "dst_port")
                        + "|"
                        + intField(fields, "protocol_number");
        return UUID.nameUUIDFromBytes(material.getBytes(StandardCharsets.UTF_8));
    }

    private static String stringField(Map<String, Object> fields, String key) {
        Object value = requiredField(fields, key);
        return value.toString();
    }

    private static int intField(Map<String, Object> fields, String key) {
        Object value = requiredField(fields, key);
        if (value instanceof Number number) {
            return number.intValue();
        }
        return Integer.parseInt(value.toString());
    }

    private static long longField(Map<String, Object> fields, String key) {
        Object value = requiredField(fields, key);
        if (value instanceof Number number) {
            return number.longValue();
        }
        return Long.parseLong(value.toString());
    }

    private static Instant instantField(Map<String, Object> fields, String key) {
        Object value = requiredField(fields, key);
        if (value instanceof Instant instant) {
            return instant;
        }
        return Instant.parse(value.toString());
    }

    private static Object requiredField(Map<String, Object> fields, String key) {
        Object value = fields.get(key);
        if (value == null) {
            throw new IllegalArgumentException("Missing NetFlow v5 field: " + key);
        }
        return value;
    }
}
