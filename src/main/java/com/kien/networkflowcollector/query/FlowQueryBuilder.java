package com.kien.networkflowcollector.query;

import com.kien.networkflowcollector.common.IpAddressSupport;
import com.kien.networkflowcollector.storage.AggQuery;
import com.kien.networkflowcollector.storage.FlowQuery;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Component;

@Component
public class FlowQueryBuilder {

    public static final String DEFAULT_SORT = "ts_start,desc";

    static final int DEFAULT_FLOW_LIMIT = 50;
    static final int MAX_FLOW_LIMIT = 1000;
    static final int DEFAULT_AGGREGATION_LIMIT = 10;
    static final int MAX_AGGREGATION_LIMIT = 100;

    private static final Set<String> SUPPORTED_PROTOCOLS = Set.of("tcp", "udp", "icmp");

    public BuiltFlowQuery flowQuery(
            String startTime,
            String endTime,
            String srcIp,
            String srcPort,
            String dstIp,
            String dstPort,
            String protocol,
            String sourceType,
            String limit,
            String sort,
            boolean cursorPresent) {
        String normalizedSort = normalizedSort(sort);
        Instant from = requiredInstant(startTime, "start_time");
        Instant to = requiredInstant(endTime, "end_time");
        validateTimeRange(from, to);
        return new BuiltFlowQuery(
                new FlowQuery(
                        from,
                        to,
                        ipFilter(srcIp, "src_ip"),
                        port(srcPort, "src_port"),
                        ipFilter(dstIp, "dst_ip"),
                        port(dstPort, "dst_port"),
                        protocol(protocol),
                        textOrNull(sourceType),
                        flowLimit(limit, cursorPresent)),
                normalizedSort);
    }

    public BuiltAggregationQuery aggregationQuery(
            String startTime, String endTime, String metric, String limit) {
        Instant from = requiredInstant(startTime, "start_time");
        Instant to = requiredInstant(endTime, "end_time");
        validateTimeRange(from, to);
        AggQuery.Metric parsedMetric = metric(metric);
        return new BuiltAggregationQuery(
                new AggQuery(from, to, aggregationLimit(limit), parsedMetric),
                parsedMetric.name().toLowerCase(Locale.ROOT));
    }

    public UUID flowId(String value) {
        String text = textOrNull(value);
        if (text == null) {
            throw new QueryValidationException("INVALID_FLOW_ID", "flow_id is required");
        }
        try {
            return UUID.fromString(text);
        } catch (IllegalArgumentException e) {
            throw new QueryValidationException("INVALID_FLOW_ID", "flow_id must be a valid UUID");
        }
    }

    private static Instant requiredInstant(String value, String name) {
        String text = textOrNull(value);
        if (text == null) {
            throw new QueryValidationException("MISSING_PARAMETER", name + " is required");
        }
        try {
            return Instant.parse(text);
        } catch (DateTimeParseException e) {
            throw new QueryValidationException(
                    "INVALID_TIMESTAMP", name + " must be an RFC3339 timestamp");
        }
    }

    private static void validateTimeRange(Instant from, Instant to) {
        if (!from.isBefore(to)) {
            throw new QueryValidationException("INVALID_TIME_RANGE", "start_time must be before end_time");
        }
    }

    private static String ipFilter(String value, String name) {
        String text = textOrNull(value);
        if (text == null) {
            return null;
        }
        if (text.contains("/")) {
            if (!IpAddressSupport.isCidr(text)) {
                throw new QueryValidationException(
                        "INVALID_PARAMETER", name + " must be an IP literal or CIDR range");
            }
            return text;
        }
        if (!IpAddressSupport.isIpLiteral(text)) {
            throw new QueryValidationException("INVALID_PARAMETER", name + " must be an IP literal");
        }
        return text;
    }

    private static Integer port(String value, String name) {
        String text = textOrNull(value);
        if (text == null) {
            return null;
        }
        int parsed = intValue(text, name);
        if (parsed < 0 || parsed > 65535) {
            throw new QueryValidationException(
                    "INVALID_PARAMETER", name + " must be between 0 and 65535");
        }
        return parsed;
    }

    private static String protocol(String value) {
        String text = lowerTextOrNull(value);
        if (text == null) {
            return null;
        }
        if (!SUPPORTED_PROTOCOLS.contains(text)) {
            throw new QueryValidationException("INVALID_PARAMETER", "protocol must be tcp, udp, or icmp");
        }
        return text;
    }

    private static int flowLimit(String value, boolean cursorPresent) {
        String text = textOrNull(value);
        if (text == null) {
            return cursorPresent ? 0 : DEFAULT_FLOW_LIMIT;
        }
        int parsed = intValue(text, "limit");
        if (parsed < 1 || parsed > MAX_FLOW_LIMIT) {
            throw new QueryValidationException(
                    "INVALID_LIMIT", "limit must be between 1 and " + MAX_FLOW_LIMIT);
        }
        return parsed;
    }

    private static int aggregationLimit(String value) {
        String text = textOrNull(value);
        if (text == null) {
            return DEFAULT_AGGREGATION_LIMIT;
        }
        int parsed = intValue(text, "limit");
        if (parsed < 1 || parsed > MAX_AGGREGATION_LIMIT) {
            throw new QueryValidationException(
                    "INVALID_LIMIT", "limit must be between 1 and " + MAX_AGGREGATION_LIMIT);
        }
        return parsed;
    }

    private static AggQuery.Metric metric(String value) {
        String text = lowerTextOrNull(value);
        if (text == null) {
            throw new QueryValidationException("MISSING_PARAMETER", "metric is required");
        }
        return switch (text) {
            case "bytes" -> AggQuery.Metric.BYTES;
            case "packets" -> AggQuery.Metric.PACKETS;
            case "flows" -> AggQuery.Metric.FLOWS;
            default -> throw new QueryValidationException(
                    "INVALID_PARAMETER", "metric must be bytes, packets, or flows");
        };
    }

    private static String normalizedSort(String value) {
        String text = lowerTextOrNull(value);
        if (text == null) {
            return DEFAULT_SORT;
        }
        if (!DEFAULT_SORT.equals(text)) {
            throw new QueryValidationException("UNSUPPORTED_SORT", "sort must be ts_start,desc");
        }
        return text;
    }

    private static int intValue(String value, String name) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new QueryValidationException("INVALID_PARAMETER", name + " must be an integer");
        }
    }

    private static String lowerTextOrNull(String value) {
        String text = textOrNull(value);
        return text == null ? null : text.toLowerCase(Locale.ROOT);
    }

    private static String textOrNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }

    public record BuiltFlowQuery(FlowQuery query, String sort) {}

    public record BuiltAggregationQuery(AggQuery query, String metric) {}
}
