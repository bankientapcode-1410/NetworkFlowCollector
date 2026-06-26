package com.kien.networkflowcollector.collectors.zeek;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

public class ZeekConnLogDecoder {

    private static final TypeReference<Map<String, Object>> STRING_OBJECT_MAP =
            new TypeReference<>() {};

    private final ObjectMapper objectMapper =
            new ObjectMapper().enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);

    private String separator = "\t";
    private String setSeparator = ",";
    private String emptyField = "(empty)";
    private String unsetField = "-";
    private String path;
    private List<String> fieldNames = List.of();
    private List<String> typeNames = List.of();

    public synchronized Optional<RawFlowRecord> decodeLine(
            String line, String exporterIp, Instant receivedAt) {
        Objects.requireNonNull(line, "line");
        Objects.requireNonNull(exporterIp, "exporterIp");
        Objects.requireNonNull(receivedAt, "receivedAt");

        if (line.isBlank()) {
            return Optional.empty();
        }
        if (line.startsWith("#")) {
            handleDirective(line);
            return Optional.empty();
        }
        if (line.startsWith("{")) {
            return decodeJsonLine(line, exporterIp, receivedAt);
        }
        if (path != null && !ZeekProtocol.CONN_PATH.equals(path)) {
            return Optional.empty();
        }
        if (fieldNames.isEmpty()) {
            throw new ZeekDecodeException("Zeek conn log line arrived before #fields metadata");
        }
        return Optional.of(connRecord(parseDelimitedFields(line), exporterIp, receivedAt));
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

    private Optional<RawFlowRecord> decodeJsonLine(
            String line, String exporterIp, Instant receivedAt) {
        Map<String, Object> fields;
        try {
            fields = objectMapper.readValue(line, STRING_OBJECT_MAP);
        } catch (JsonProcessingException e) {
            throw new ZeekDecodeException("Invalid Zeek JSON log line", e);
        }

        Object jsonPath = fields.get("_path");
        if (jsonPath == null) {
            jsonPath = fields.get("path");
        }
        if (jsonPath != null && !ZeekProtocol.CONN_PATH.equals(jsonPath.toString())) {
            return Optional.empty();
        }
        return Optional.of(connRecord(fields, exporterIp, receivedAt));
    }

    private void handleDirective(String line) {
        String directive = firstToken(line);
        String value = directiveValue(line, directive);
        switch (directive) {
            case "#separator" -> separator = unescape(value);
            case "#set_separator" -> setSeparator = value;
            case "#empty_field" -> emptyField = value;
            case "#unset_field" -> unsetField = value;
            case "#path" -> path = value;
            case "#fields" -> fieldNames = split(value, separator);
            case "#types" -> typeNames = split(value, separator);
            default -> {
                // Other Zeek metadata such as #open and #close does not affect decoding.
            }
        }
    }

    private Map<String, Object> parseDelimitedFields(String line) {
        List<String> values = split(line, separator);
        if (values.size() < fieldNames.size()) {
            throw new ZeekDecodeException(
                    "Zeek conn log has "
                            + values.size()
                            + " fields but expected "
                            + fieldNames.size());
        }

        Map<String, Object> fields = new LinkedHashMap<>();
        for (int i = 0; i < fieldNames.size(); i++) {
            String fieldName = fieldNames.get(i);
            parseValue(values.get(i), typeAt(i)).ifPresent(value -> fields.put(fieldName, value));
        }
        return fields;
    }

    private RawFlowRecord connRecord(
            Map<String, Object> sourceFields, String exporterIp, Instant receivedAt) {
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("zeek_path", ZeekProtocol.CONN_PATH);
        for (Map.Entry<String, Object> entry : sourceFields.entrySet()) {
            if (entry.getValue() != null) {
                fields.put(entry.getKey(), entry.getValue());
            }
        }

        Instant tsStart = instantField(sourceFields, "ts").orElse(receivedAt);
        long durationMs = intervalFieldMillis(sourceFields, "duration").orElse(0L);
        Instant tsEnd = tsStart.plusMillis(durationMs);
        String protocol = ZeekProtocol.protocolName(sourceFields.get("proto"));
        long bytes = sumLongFields(sourceFields, "orig_bytes", "resp_bytes")
                .orElseGet(() -> sumLongFields(sourceFields, "orig_ip_bytes", "resp_ip_bytes").orElse(0L));
        long packets = sumLongFields(sourceFields, "orig_pkts", "resp_pkts").orElse(0L);

        fields.put("ts_start", tsStart);
        fields.put("ts_end", tsEnd);
        fields.put("duration_ms", durationMs);
        putIfPresent(fields, "uid", stringField(sourceFields, "uid"));
        putIfPresent(fields, "src_ip", stringField(sourceFields, "id.orig_h"));
        putIfPresent(fields, "src_port", intField(sourceFields, "id.orig_p"));
        putIfPresent(fields, "dst_ip", stringField(sourceFields, "id.resp_h"));
        putIfPresent(fields, "dst_port", intField(sourceFields, "id.resp_p"));
        fields.put("protocol", protocol);
        fields.put("protocol_number", ZeekProtocol.protocolNumber(protocol));
        fields.put("bytes", bytes);
        fields.put("packets", packets);
        fields.put("sampled", false);

        return new RawFlowRecord(ZeekProtocol.CONN_SOURCE_TYPE, exporterIp, receivedAt, fields);
    }

    private Optional<Object> parseValue(String value, String type) {
        if (value.equals(unsetField)) {
            return Optional.empty();
        }
        if (value.equals(emptyField)) {
            return Optional.of("");
        }
        return Optional.of(
                switch (type) {
                    case "time" -> ZeekProtocol.timestamp(value);
                    case "interval" -> new BigDecimal(value);
                    case "count" -> Long.parseLong(value);
                    case "port" -> Integer.parseInt(value);
                    case "bool" -> parseBoolean(value);
                    default -> type.startsWith("set[") ? split(value, setSeparator) : value;
                });
    }

    private String typeAt(int index) {
        if (index >= typeNames.size()) {
            return "string";
        }
        return typeNames.get(index);
    }

    private Optional<Instant> instantField(Map<String, Object> fields, String key) {
        Object value = fields.get(key);
        if (value == null) {
            return Optional.empty();
        }
        return Optional.of(ZeekProtocol.timestamp(value));
    }

    private Optional<Long> intervalFieldMillis(Map<String, Object> fields, String key) {
        Object value = fields.get(key);
        if (value == null) {
            return Optional.empty();
        }
        return Optional.of(ZeekProtocol.intervalMillis(value));
    }

    private Optional<String> stringField(Map<String, Object> fields, String key) {
        Object value = fields.get(key);
        return value == null ? Optional.empty() : Optional.of(value.toString());
    }

    private Optional<Integer> intField(Map<String, Object> fields, String key) {
        Object value = fields.get(key);
        if (value == null) {
            return Optional.empty();
        }
        if (value instanceof Number number) {
            return Optional.of(number.intValue());
        }
        return Optional.of(Integer.parseInt(value.toString()));
    }

    private Optional<Long> sumLongFields(Map<String, Object> fields, String firstKey, String secondKey) {
        Optional<Long> first = longField(fields, firstKey);
        Optional<Long> second = longField(fields, secondKey);
        if (first.isEmpty() && second.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(first.orElse(0L) + second.orElse(0L));
    }

    private Optional<Long> longField(Map<String, Object> fields, String key) {
        Object value = fields.get(key);
        if (value == null) {
            return Optional.empty();
        }
        if (value instanceof Number number) {
            return Optional.of(number.longValue());
        }
        return Optional.of(Long.parseLong(value.toString()));
    }

    private static void putIfPresent(
            Map<String, Object> fields, String key, Optional<?> value) {
        value.ifPresent(actual -> fields.put(key, actual));
    }

    private static boolean parseBoolean(String value) {
        return "T".equals(value) || "true".equalsIgnoreCase(value);
    }

    private static String firstToken(String line) {
        int end = 0;
        while (end < line.length() && !Character.isWhitespace(line.charAt(end))) {
            end++;
        }
        return line.substring(0, end);
    }

    private static String directiveValue(String line, String directive) {
        return line.substring(directive.length()).stripLeading();
    }

    private static List<String> split(String value, String separator) {
        if (value.isEmpty()) {
            return List.of("");
        }
        return List.of(value.split(Pattern.quote(separator), -1));
    }

    private static String unescape(String value) {
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char current = value.charAt(i);
            if (current != '\\' || i + 1 >= value.length()) {
                out.append(current);
                continue;
            }
            char escaped = value.charAt(++i);
            switch (escaped) {
                case 'n' -> out.append('\n');
                case 'r' -> out.append('\r');
                case 't' -> out.append('\t');
                case 'x' -> {
                    if (i + 2 >= value.length()) {
                        throw new ZeekDecodeException("Invalid Zeek escape: " + value);
                    }
                    String hex = value.substring(i + 1, i + 3);
                    out.append((char) Integer.parseInt(hex, 16));
                    i += 2;
                }
                default -> out.append(escaped);
            }
        }
        return out.toString();
    }
}
