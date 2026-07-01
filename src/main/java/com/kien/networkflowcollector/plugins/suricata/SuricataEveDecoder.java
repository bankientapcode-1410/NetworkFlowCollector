package com.kien.networkflowcollector.plugins.suricata;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public class SuricataEveDecoder {

    private static final TypeReference<Map<String, Object>> STRING_OBJECT_MAP =
            new TypeReference<>() {};

    private final ObjectMapper objectMapper =
            new ObjectMapper().enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);

    public Optional<RawFlowRecord> decodeLine(String line, String exporterIp, Instant receivedAt) {
        Objects.requireNonNull(line, "line");
        Objects.requireNonNull(exporterIp, "exporterIp");
        Objects.requireNonNull(receivedAt, "receivedAt");

        if (line.isBlank()) {
            return Optional.empty();
        }
        String trimmed = line.stripLeading();
        if (!trimmed.startsWith("{")) {
            throw new SuricataDecodeException("Suricata EVE line is not JSON");
        }

        Map<String, Object> event;
        try {
            event = objectMapper.readValue(trimmed, STRING_OBJECT_MAP);
        } catch (JsonProcessingException e) {
            throw new SuricataDecodeException("Invalid Suricata EVE JSON line", e);
        }

        String eventType = stringField(event, "event_type").orElse("");
        if (!SuricataProtocol.FLOW_EVENT_TYPE.equals(eventType)) {
            return Optional.empty();
        }
        return Optional.of(flowRecord(event, exporterIp, receivedAt));
    }

    public List<RawFlowRecord> decodeLines(
            Iterable<String> lines, String exporterIp, Instant receivedAt) {
        Objects.requireNonNull(lines, "lines");

        List<RawFlowRecord> records = new ArrayList<>();
        for (String line : lines) {
            decodeLine(line, exporterIp, receivedAt).ifPresent(records::add);
        }
        return records;
    }

    private RawFlowRecord flowRecord(
            Map<String, Object> event, String exporterIp, Instant receivedAt) {
        Map<String, Object> flow = nestedMap(event, "flow").orElse(Map.of());
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("suricata_event_type", SuricataProtocol.FLOW_EVENT_TYPE);
        copyTopLevelFields(fields, event);
        copyNestedFields(fields, "flow_", flow);

        Instant eventTimestamp = timestampField(event, "timestamp").orElse(receivedAt);
        Optional<Instant> flowStart = timestampField(flow, "start");
        Optional<Instant> flowEnd = timestampField(flow, "end");
        Optional<Long> ageMs = intervalFieldMillis(flow, "age");
        Instant tsStart = flowStart.orElse(eventTimestamp);
        Instant tsEnd = flowEnd.orElseGet(() -> ageMs.map(tsStart::plusMillis).orElse(eventTimestamp));
        long durationMs =
                flowStart.isPresent() && flowEnd.isPresent()
                        ? SuricataProtocol.durationMillis(tsStart, tsEnd)
                        : ageMs.orElseGet(() -> SuricataProtocol.durationMillis(tsStart, tsEnd));
        String protocol = SuricataProtocol.protocolName(event.get("proto"));

        fields.put("ts_start", tsStart);
        fields.put("ts_end", tsEnd);
        fields.put("duration_ms", durationMs);
        putIfPresent(fields, "flow_id", longField(event, "flow_id"));
        putIfPresent(fields, "src_ip", stringField(event, "src_ip"));
        putIfPresent(fields, "src_port", intField(event, "src_port"));
        putIfPresent(fields, "dst_ip", stringField(event, "dest_ip").or(() -> stringField(event, "dst_ip")));
        putIfPresent(fields, "dst_port", intField(event, "dest_port").or(() -> intField(event, "dst_port")));
        fields.put("protocol", protocol);
        fields.put("protocol_number", SuricataProtocol.protocolNumber(protocol));
        fields.put("bytes", sumLongFields(flow, "bytes_toserver", "bytes_toclient").orElse(0L));
        fields.put("packets", sumLongFields(flow, "pkts_toserver", "pkts_toclient").orElse(0L));
        putIfPresent(fields, "app_proto", stringField(event, "app_proto"));
        putIfPresent(fields, "flow_state", stringField(flow, "state"));
        putIfPresent(fields, "flow_reason", stringField(flow, "reason"));
        putIfPresent(fields, "alerted", booleanField(flow, "alerted"));
        putIfPresent(fields, "tcp_flags", tcpFlags(event, flow));
        fields.put("sampled", false);

        return new RawFlowRecord(SuricataProtocol.FLOW_SOURCE_TYPE, exporterIp, receivedAt, fields);
    }

    private static void copyTopLevelFields(Map<String, Object> fields, Map<String, Object> event) {
        for (Map.Entry<String, Object> entry : event.entrySet()) {
            if (entry.getValue() != null && !"flow".equals(entry.getKey())) {
                fields.put(entry.getKey(), entry.getValue());
            }
        }
    }

    private static void copyNestedFields(
            Map<String, Object> fields, String prefix, Map<String, Object> nested) {
        for (Map.Entry<String, Object> entry : nested.entrySet()) {
            if (entry.getValue() != null) {
                fields.put(prefix + entry.getKey(), entry.getValue());
            }
        }
    }

    private static Optional<Map<String, Object>> nestedMap(Map<String, Object> fields, String key) {
        Object value = fields.get(key);
        if (!(value instanceof Map<?, ?> source)) {
            return Optional.empty();
        }
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : source.entrySet()) {
            if (entry.getKey() != null) {
                out.put(entry.getKey().toString(), entry.getValue());
            }
        }
        return Optional.of(out);
    }

    private static Optional<Instant> timestampField(Map<String, Object> fields, String key) {
        Object value = fields.get(key);
        if (value == null) {
            return Optional.empty();
        }
        return Optional.of(SuricataProtocol.timestamp(value));
    }

    private static Optional<Long> intervalFieldMillis(Map<String, Object> fields, String key) {
        Object value = fields.get(key);
        if (value == null) {
            return Optional.empty();
        }
        return Optional.of(SuricataProtocol.intervalMillis(value));
    }

    private static Optional<String> stringField(Map<String, Object> fields, String key) {
        Object value = fields.get(key);
        return value == null ? Optional.empty() : Optional.of(value.toString());
    }

    private static Optional<Boolean> booleanField(Map<String, Object> fields, String key) {
        Object value = fields.get(key);
        if (value == null) {
            return Optional.empty();
        }
        if (value instanceof Boolean bool) {
            return Optional.of(bool);
        }
        return Optional.of(Boolean.parseBoolean(value.toString()));
    }

    private static Optional<Integer> intField(Map<String, Object> fields, String key) {
        Object value = fields.get(key);
        if (value == null) {
            return Optional.empty();
        }
        if (value instanceof Number number) {
            return Optional.of(number.intValue());
        }
        return Optional.of(Integer.parseInt(value.toString()));
    }

    private static Optional<Long> sumLongFields(Map<String, Object> fields, String firstKey, String secondKey) {
        Optional<Long> first = longField(fields, firstKey);
        Optional<Long> second = longField(fields, secondKey);
        if (first.isEmpty() && second.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(first.orElse(0L) + second.orElse(0L));
    }

    private static Optional<Long> longField(Map<String, Object> fields, String key) {
        Object value = fields.get(key);
        if (value == null) {
            return Optional.empty();
        }
        if (value instanceof Number number) {
            return Optional.of(number.longValue());
        }
        return Optional.of(Long.parseLong(value.toString()));
    }

    private static Optional<Integer> tcpFlags(Map<String, Object> event, Map<String, Object> flow) {
        Optional<Integer> value = intLikeField(event, "tcp_flags");
        if (value.isPresent()) {
            return value;
        }
        value = intLikeField(flow, "tcp_flags");
        if (value.isPresent()) {
            return value;
        }
        return intLikeField(flow, "tcp_flags_ts");
    }

    private static Optional<Integer> intLikeField(Map<String, Object> fields, String key) {
        Object value = fields.get(key);
        if (value == null) {
            return Optional.empty();
        }
        if (value instanceof Number number) {
            return Optional.of(number.intValue());
        }
        String text = value.toString();
        try {
            return Optional.of(Integer.decode(text));
        } catch (NumberFormatException ignored) {
            return Optional.of(Integer.parseUnsignedInt(text, 16));
        }
    }

    private static void putIfPresent(Map<String, Object> fields, String key, Optional<?> value) {
        value.ifPresent(actual -> fields.put(key, actual));
    }
}
