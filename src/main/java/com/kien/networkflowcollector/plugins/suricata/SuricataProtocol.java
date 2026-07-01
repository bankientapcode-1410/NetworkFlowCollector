package com.kien.networkflowcollector.plugins.suricata;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoField;
import java.util.Locale;

final class SuricataProtocol {

    static final String COLLECTOR_TYPE = "suricata";
    static final String FLOW_SOURCE_TYPE = "suricata-flow";
    static final String FLOW_EVENT_TYPE = "flow";
    static final String DEFAULT_EXPORTER_IP = "suricata";

    private static final DateTimeFormatter SURICATA_OFFSET_TIMESTAMP =
            new DateTimeFormatterBuilder()
                    .appendPattern("yyyy-MM-dd'T'HH:mm:ss")
                    .optionalStart()
                    .appendFraction(ChronoField.NANO_OF_SECOND, 1, 9, true)
                    .optionalEnd()
                    .appendOffset("+HHMM", "Z")
                    .toFormatter(Locale.ROOT);

    private SuricataProtocol() {}

    static Instant timestamp(Object value) {
        if (value instanceof Instant instant) {
            return instant;
        }
        String text = value.toString();
        try {
            return Instant.parse(text);
        } catch (DateTimeParseException ignored) {
            // Suricata commonly emits offsets such as +0000, which Instant.parse does not accept.
        }
        try {
            return OffsetDateTime.parse(text).toInstant();
        } catch (DateTimeParseException ignored) {
            // Try Suricata's compact offset format below.
        }
        try {
            return OffsetDateTime.parse(text, SURICATA_OFFSET_TIMESTAMP).toInstant();
        } catch (DateTimeParseException e) {
            throw new SuricataDecodeException("Invalid Suricata timestamp: " + text, e);
        }
    }

    static long intervalMillis(Object secondsValue) {
        return decimal(secondsValue).movePointRight(3).setScale(0, RoundingMode.HALF_UP).longValue();
    }

    static long durationMillis(Instant start, Instant end) {
        long duration = Duration.between(start, end).toMillis();
        return Math.max(duration, 0);
    }

    static String protocolName(Object value) {
        if (value == null) {
            return "unknown";
        }
        String protocol = value.toString().trim().toLowerCase(Locale.ROOT);
        return protocol.isEmpty() ? "unknown" : protocol;
    }

    static int protocolNumber(String protocol) {
        return switch (protocolName(protocol)) {
            case "icmp" -> 1;
            case "tcp" -> 6;
            case "udp" -> 17;
            default -> 0;
        };
    }

    private static BigDecimal decimal(Object value) {
        if (value instanceof BigDecimal decimal) {
            return decimal;
        }
        if (value instanceof BigInteger bigInteger) {
            return new BigDecimal(bigInteger);
        }
        if (value instanceof Number number) {
            return BigDecimal.valueOf(number.doubleValue());
        }
        return new BigDecimal(value.toString());
    }
}
