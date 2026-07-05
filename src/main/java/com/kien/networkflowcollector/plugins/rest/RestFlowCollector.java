package com.kien.networkflowcollector.plugins.rest;

import com.fasterxml.jackson.databind.JsonNode;
import com.kien.networkflowcollector.common.IpAddressSupport;
import com.kien.networkflowcollector.kafka.PublishBackpressureException;
import com.kien.networkflowcollector.spi.CollectorConfig;
import com.kien.networkflowcollector.spi.CollectorHealth;
import com.kien.networkflowcollector.spi.CollectorStatus;
import com.kien.networkflowcollector.spi.FlowCollector;
import com.kien.networkflowcollector.spi.FlowPublisher;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicLong;

public class RestFlowCollector implements FlowCollector {

    private static final Set<String> ROOT_FIELDS =
            Set.of("source_type", "sourceType", "exporter_ip", "exporterIp", "received_at", "receivedAt", "fields");
    private static final Set<String> FLOW_FIELDS =
            Set.of(
                    "event_id",
                    "client_event_id",
                    "flow_id",
                    "src_ip",
                    "dst_ip",
                    "src_port",
                    "dst_port",
                    "protocol",
                    "proto",
                    "protocol_number",
                    "bytes",
                    "bytes_total",
                    "packets",
                    "packets_total",
                    "tcp_flags",
                    "ts_start",
                    "ts_end",
                    "start",
                    "end",
                    "duration_ms",
                    "sampled",
                    "sampling_rate",
                    "sample_pool",
                    "src_as",
                    "src_asn",
                    "dst_as",
                    "dst_asn");

    private final AtomicLong acceptedRequests = new AtomicLong();
    private final AtomicLong acceptedRecords = new AtomicLong();
    private final AtomicLong publishedRecords = new AtomicLong();
    private final AtomicLong validationErrors = new AtomicLong();
    private final AtomicLong publishErrors = new AtomicLong();

    private volatile CollectorConfig config = new CollectorConfig(false, Map.of());
    private volatile FlowPublisher publisher;
    private volatile CollectorStatus status = CollectorStatus.STOPPED;
    private volatile String message = "not initialized";
    private volatile int maxBatchSize = RestProtocol.DEFAULT_MAX_BATCH_SIZE;
    private volatile Instant lastRecordAt;

    @Override
    public String type() {
        return RestProtocol.COLLECTOR_TYPE;
    }

    @Override
    public Set<String> supportedSourceTypes() {
        return Set.of(RestProtocol.SOURCE_TYPE);
    }

    @Override
    public synchronized void init(CollectorConfig config, FlowPublisher publisher) {
        this.config = config == null ? new CollectorConfig(true, Map.of()) : config;
        this.publisher = publisher;
        Map<String, Object> properties = this.config.properties();
        this.maxBatchSize =
                intProperty(properties, "maxBatchSize", "max_batch_size", RestProtocol.DEFAULT_MAX_BATCH_SIZE);

        if (!this.config.enabled()) {
            status = CollectorStatus.STOPPED;
            message = "collector disabled";
            return;
        }
        if (publisher == null) {
            status = CollectorStatus.DOWN;
            message = "publisher unavailable";
            throw new NullPointerException("publisher");
        }
        status = CollectorStatus.STOPPED;
        message = "initialized for " + RestProtocol.ENDPOINT + " max_batch_size=" + maxBatchSize;
    }

    @Override
    public synchronized void start() {
        if (!config.enabled()) {
            status = CollectorStatus.STOPPED;
            message = "collector disabled";
            return;
        }
        Objects.requireNonNull(publisher, "publisher");
        status = CollectorStatus.UP;
        message = "accepting REST ingest on " + RestProtocol.ENDPOINT;
    }

    @Override
    public synchronized void stop() {
        status = CollectorStatus.STOPPED;
        message = "stopped";
    }

    @Override
    public CollectorHealth health() {
        CollectorStatus currentStatus = status;
        if (currentStatus == CollectorStatus.UP && (validationErrors.get() > 0 || publishErrors.get() > 0)) {
            currentStatus = CollectorStatus.DEGRADED;
        }
        String healthMessage =
                message
                        + " requests="
                        + acceptedRequests.get()
                        + " accepted_records="
                        + acceptedRecords.get()
                        + " published_records="
                        + publishedRecords.get()
                        + " validation_errors="
                        + validationErrors.get()
                        + " publish_errors="
                        + publishErrors.get();
        return new CollectorHealth(currentStatus, healthMessage, Instant.now(), lastRecordAt);
    }

    RestIngestReceipt ingest(JsonNode payload) {
        ensureReady();

        List<RestInputRecord> inputRecords;
        try {
            inputRecords = parsePayload(payload);
        } catch (RestIngestValidationException e) {
            validationErrors.incrementAndGet();
            message = "REST ingest validation failed: " + e.getMessage();
            throw e;
        }

        String batchId = UUID.randomUUID().toString();
        Instant acceptedAt = Instant.now();
        List<RawFlowRecord> rawRecords = new ArrayList<>(inputRecords.size());
        for (int index = 0; index < inputRecords.size(); index++) {
            RestInputRecord input = inputRecords.get(index);
            Map<String, Object> fields = new LinkedHashMap<>(input.fields());
            fields.put("rest_batch_id", batchId);
            fields.put("rest_batch_index", index);
            Instant receivedAt = input.receivedAt() == null ? acceptedAt : input.receivedAt();
            rawRecords.add(new RawFlowRecord(RestProtocol.SOURCE_TYPE, input.exporterIp(), receivedAt, fields));
        }

        publish(rawRecords);
        acceptedRequests.incrementAndGet();
        acceptedRecords.addAndGet(rawRecords.size());
        publishedRecords.addAndGet(rawRecords.size());
        lastRecordAt = acceptedAt;
        message = "accepted REST ingest batch " + batchId + " records=" + rawRecords.size();
        return new RestIngestReceipt(batchId, rawRecords.size(), acceptedAt);
    }

    private void ensureReady() {
        if (!config.enabled()) {
            throw new RestIngestUnavailableException("REST ingest collector is disabled");
        }
        if (status != CollectorStatus.UP || publisher == null) {
            throw new RestIngestUnavailableException("REST ingest collector is not ready");
        }
    }

    private List<RestInputRecord> parsePayload(JsonNode payload) {
        if (payload == null || payload.isNull()) {
            throw new RestIngestValidationException("request body is required");
        }
        if (payload.isArray()) {
            if (payload.isEmpty()) {
                throw new RestIngestValidationException("batch must contain at least one record");
            }
            if (payload.size() > maxBatchSize) {
                throw new RestIngestValidationException(
                        "batch size " + payload.size() + " exceeds max_batch_size " + maxBatchSize);
            }
            List<RestInputRecord> records = new ArrayList<>(payload.size());
            for (int index = 0; index < payload.size(); index++) {
                records.add(parseRecord(payload.get(index), "records[" + index + "]"));
            }
            return List.copyOf(records);
        }
        if (payload.isObject()) {
            return List.of(parseRecord(payload, "record"));
        }
        throw new RestIngestValidationException("request body must be an object or array");
    }

    private RestInputRecord parseRecord(JsonNode node, String path) {
        if (node == null || !node.isObject()) {
            throw new RestIngestValidationException(path + " must be an object");
        }
        rejectUnknownFields(node, ROOT_FIELDS, path);

        String sourceType = optionalText(node, path, "source_type", "sourceType");
        if (sourceType != null && !RestProtocol.SOURCE_TYPE.equals(sourceType)) {
            throw new RestIngestValidationException(path + ".source_type must be rest");
        }
        Instant receivedAtValue = null;
        JsonNode receivedAt = aliasNode(node, "received_at", "receivedAt");
        if (receivedAt != null && !receivedAt.isNull()) {
            receivedAtValue = parseTimestamp(receivedAt, path + ".received_at");
        }

        String exporterIp = requiredText(node, path, "exporter_ip", "exporterIp");
        if (!IpAddressSupport.isIpLiteral(exporterIp)) {
            throw new RestIngestValidationException(path + ".exporter_ip must be an IP literal");
        }

        JsonNode fieldsNode = node.get("fields");
        if (fieldsNode == null || !fieldsNode.isObject()) {
            throw new RestIngestValidationException(path + ".fields must be an object");
        }
        rejectUnknownFields(fieldsNode, FLOW_FIELDS, path + ".fields");
        validateFields(fieldsNode, path + ".fields");
        return new RestInputRecord(exporterIp, receivedAtValue, fieldMap(fieldsNode, path + ".fields"));
    }

    private void validateFields(JsonNode fields, String path) {
        String srcIp = requiredText(fields, path, "src_ip");
        String dstIp = requiredText(fields, path, "dst_ip");
        if (!IpAddressSupport.isIpLiteral(srcIp)) {
            throw new RestIngestValidationException(path + ".src_ip must be an IP literal");
        }
        if (!IpAddressSupport.isIpLiteral(dstIp)) {
            throw new RestIngestValidationException(path + ".dst_ip must be an IP literal");
        }

        requiredInt(fields, path, 0, 65_535, "src_port");
        requiredInt(fields, path, 0, 65_535, "dst_port");
        requiredLong(fields, path, 0, Long.MAX_VALUE, "bytes", "bytes_total");
        requiredLong(fields, path, 0, Long.MAX_VALUE, "packets", "packets_total");

        JsonNode protocolNode = requiredAlias(fields, path, "protocol", "proto", "protocol_number");
        int protocolNumber = protocolNumber(protocolNode, path + ".protocol");
        if (protocolNumber < 0 || protocolNumber > 255) {
            throw new RestIngestValidationException(path + ".protocol must be between 0 and 255");
        }

        Instant tsStart = parseTimestamp(requiredAlias(fields, path, "ts_start", "start"), path + ".ts_start");
        Instant tsEnd = parseTimestamp(requiredAlias(fields, path, "ts_end", "end"), path + ".ts_end");
        if (tsStart.isAfter(tsEnd)) {
            throw new RestIngestValidationException(path + ".ts_start must be before or equal to ts_end");
        }

        JsonNode tcpFlags = fields.get("tcp_flags");
        if (tcpFlags != null && !tcpFlags.isNull()) {
            parseTcpFlags(tcpFlags, path + ".tcp_flags");
        }
        JsonNode duration = fields.get("duration_ms");
        if (duration != null && !duration.isNull()) {
            parseLong(duration, path + ".duration_ms", 0, Long.MAX_VALUE);
        }
        validateSampling(fields, path);
    }

    private void validateSampling(JsonNode fields, String path) {
        JsonNode sampledNode = fields.get("sampled");
        Boolean sampled = sampledNode == null || sampledNode.isNull() ? null : parseBoolean(sampledNode, path + ".sampled");
        JsonNode samplingRate = fields.get("sampling_rate");
        JsonNode samplePool = fields.get("sample_pool");
        boolean hasSamplingRate = samplingRate != null && !samplingRate.isNull();
        boolean hasSamplePool = samplePool != null && !samplePool.isNull();

        if (hasSamplingRate) {
            parseLong(samplingRate, path + ".sampling_rate", 1, Long.MAX_VALUE);
        }
        if (hasSamplePool) {
            parseLong(samplePool, path + ".sample_pool", 1, Long.MAX_VALUE);
        }
        if (Boolean.FALSE.equals(sampled) && (hasSamplingRate || hasSamplePool)) {
            throw new RestIngestValidationException(
                    path + ".sampled=false must not include sampling_rate or sample_pool");
        }
        if ((Boolean.TRUE.equals(sampled) || hasSamplePool) && !hasSamplingRate) {
            throw new RestIngestValidationException(path + ".sampled flows require sampling_rate");
        }
    }

    private Map<String, Object> fieldMap(JsonNode fieldsNode, String path) {
        Map<String, Object> fields = new LinkedHashMap<>();
        Iterator<Map.Entry<String, JsonNode>> entries = fieldsNode.fields();
        while (entries.hasNext()) {
            Map.Entry<String, JsonNode> entry = entries.next();
            JsonNode value = entry.getValue();
            if (value == null || value.isNull()) {
                continue;
            }
            fields.put(entry.getKey(), scalarValue(value, path + "." + entry.getKey()));
        }
        return Map.copyOf(fields);
    }

    private void publish(List<RawFlowRecord> rawRecords) {
        List<CompletableFuture<Void>> futures = new ArrayList<>(rawRecords.size());
        for (RawFlowRecord rawRecord : rawRecords) {
            try {
                CompletionStage<Void> stage = publisher.publish(rawRecord);
                futures.add(stage == null ? CompletableFuture.completedFuture(null) : stage.toCompletableFuture());
            } catch (RuntimeException e) {
                handlePublishFailure(e);
            }
        }

        try {
            CompletableFuture.allOf(futures.toArray(CompletableFuture[]::new)).join();
        } catch (CompletionException e) {
            handlePublishFailure(e.getCause() == null ? e : e.getCause());
        }
    }

    private void handlePublishFailure(Throwable error) {
        publishErrors.incrementAndGet();
        Throwable cause = unwrap(error);
        message = "failed to publish REST ingest record: " + cause.getMessage();
        if (cause instanceof PublishBackpressureException) {
            throw new RestIngestBackpressureException("publisher is applying backpressure", cause);
        }
        throw new RestIngestPublishException("publisher is unavailable", cause);
    }

    private static Throwable unwrap(Throwable error) {
        Throwable current = error;
        while (current instanceof CompletionException && current.getCause() != null) {
            current = current.getCause();
        }
        return current;
    }

    private static void rejectUnknownFields(JsonNode node, Set<String> allowedFields, String path) {
        Iterator<String> names = node.fieldNames();
        while (names.hasNext()) {
            String name = names.next();
            if (!allowedFields.contains(name)) {
                throw new RestIngestValidationException(path + "." + name + " is not a recognized field");
            }
        }
    }

    private static JsonNode requiredAlias(JsonNode node, String path, String... aliases) {
        JsonNode value = aliasNode(node, aliases);
        if (value == null || value.isNull()) {
            throw new RestIngestValidationException(path + "." + aliases[0] + " is required");
        }
        return value;
    }

    private static String requiredText(JsonNode node, String path, String... aliases) {
        JsonNode value = requiredAlias(node, path, aliases);
        if (!value.isTextual()) {
            throw new RestIngestValidationException(path + "." + aliases[0] + " must be a string");
        }
        String text = value.asText().trim();
        if (text.isEmpty()) {
            throw new RestIngestValidationException(path + "." + aliases[0] + " must not be blank");
        }
        return text;
    }

    private static String optionalText(JsonNode node, String path, String... aliases) {
        JsonNode value = aliasNode(node, aliases);
        if (value == null || value.isNull()) {
            return null;
        }
        if (!value.isTextual()) {
            throw new RestIngestValidationException(path + "." + aliases[0] + " must be a string");
        }
        String text = value.asText().trim();
        return text.isEmpty() ? null : text;
    }

    private static JsonNode aliasNode(JsonNode node, String... aliases) {
        JsonNode selected = null;
        for (String alias : aliases) {
            JsonNode value = node.get(alias);
            if (value == null) {
                continue;
            }
            if (selected != null && !selected.equals(value)) {
                throw new RestIngestValidationException("conflicting alias values for " + aliases[0]);
            }
            selected = value;
        }
        return selected;
    }

    private static int requiredInt(JsonNode node, String path, int min, int max, String... aliases) {
        return parseInt(requiredAlias(node, path, aliases), path + "." + aliases[0], min, max);
    }

    private static long requiredLong(JsonNode node, String path, long min, long max, String... aliases) {
        return parseLong(requiredAlias(node, path, aliases), path + "." + aliases[0], min, max);
    }

    private static int parseInt(JsonNode value, String path, int min, int max) {
        long parsed = parseLong(value, path, min, max);
        if (parsed < Integer.MIN_VALUE || parsed > Integer.MAX_VALUE) {
            throw new RestIngestValidationException(path + " is out of integer range");
        }
        return (int) parsed;
    }

    private static int parseTcpFlags(JsonNode value, String path) {
        if (!value.isTextual()) {
            return parseInt(value, path, 0, 65_535);
        }

        String text = value.asText().trim();
        int parsed;
        try {
            parsed = Integer.decode(text);
        } catch (NumberFormatException decimalOrPrefixedFailure) {
            try {
                parsed = Integer.parseUnsignedInt(text, 16);
            } catch (NumberFormatException hexFailure) {
                throw new RestIngestValidationException(path + " must be an integer", decimalOrPrefixedFailure);
            }
        }
        if (parsed < 0 || parsed > 65_535) {
            throw new RestIngestValidationException(path + " is out of range");
        }
        return parsed;
    }

    private static long parseLong(JsonNode value, String path, long min, long max) {
        long parsed;
        if (value.isIntegralNumber() && value.canConvertToLong()) {
            parsed = value.longValue();
        } else if (value.isTextual()) {
            try {
                parsed = Long.parseLong(value.asText().trim());
            } catch (NumberFormatException e) {
                throw new RestIngestValidationException(path + " must be an integer", e);
            }
        } else {
            throw new RestIngestValidationException(path + " must be an integer");
        }
        if (parsed < min || parsed > max) {
            throw new RestIngestValidationException(path + " is out of range");
        }
        return parsed;
    }

    private static int protocolNumber(JsonNode value, String path) {
        if (value.isIntegralNumber() && value.canConvertToInt()) {
            return value.intValue();
        }
        if (value.isTextual()) {
            return RestProtocol.protocolNumber(value.asText());
        }
        throw new RestIngestValidationException(path + " must be a string or integer");
    }

    private static Instant parseTimestamp(JsonNode value, String path) {
        try {
            if (value.isIntegralNumber() && value.canConvertToLong()) {
                return RestProtocol.timestamp(value.longValue());
            }
            if (value.isTextual()) {
                return RestProtocol.timestamp(value.asText());
            }
            throw new RestIngestValidationException(path + " must be an RFC3339 string or epoch milliseconds");
        } catch (RestIngestValidationException e) {
            throw new RestIngestValidationException(path + " is invalid", e);
        }
    }

    private static Boolean parseBoolean(JsonNode value, String path) {
        if (value.isBoolean()) {
            return value.booleanValue();
        }
        if (value.isTextual()) {
            String text = value.asText().trim();
            if ("true".equalsIgnoreCase(text)) {
                return true;
            }
            if ("false".equalsIgnoreCase(text)) {
                return false;
            }
        }
        throw new RestIngestValidationException(path + " must be a boolean");
    }

    private static Object scalarValue(JsonNode value, String path) {
        if (value.isTextual()) {
            return value.asText();
        }
        if (value.isIntegralNumber()) {
            if (value.canConvertToLong()) {
                return value.longValue();
            }
            return value.bigIntegerValue();
        }
        if (value.isFloatingPointNumber() || value.isBigDecimal()) {
            BigDecimal decimal = value.decimalValue();
            return decimal.stripTrailingZeros();
        }
        if (value.isBoolean()) {
            return value.booleanValue();
        }
        if (value.isBigInteger()) {
            BigInteger bigInteger = value.bigIntegerValue();
            return bigInteger.bitLength() < Long.SIZE ? bigInteger.longValue() : bigInteger;
        }
        throw new RestIngestValidationException(path + " must be a scalar JSON value");
    }

    private static int intProperty(Map<String, Object> properties, String primaryKey, String aliasKey, int defaultValue) {
        Object value = properties.get(primaryKey);
        if (value == null) {
            value = properties.get(aliasKey);
        }
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Number number) {
            return number.intValue();
        }
        return Integer.parseInt(value.toString());
    }

    private record RestInputRecord(String exporterIp, Instant receivedAt, Map<String, Object> fields) {}
}
