package com.kien.networkflowcollector.plugins.rest;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Locale;

final class RestProtocol {

    static final String COLLECTOR_TYPE = "rest";
    static final String SOURCE_TYPE = "rest";
    static final String ENDPOINT = "/ingest";
    static final int DEFAULT_MAX_BATCH_SIZE = 5_000;

    private RestProtocol() {}

    static Instant timestamp(Object value) {
        if (value instanceof Instant instant) {
            return instant;
        }
        if (value instanceof Number number) {
            return Instant.ofEpochMilli(number.longValue());
        }
        String text = value.toString().trim();
        if (text.isEmpty()) {
            throw new RestIngestValidationException("timestamp must not be blank");
        }
        try {
            return Instant.parse(text);
        } catch (DateTimeParseException e) {
            try {
                return Instant.ofEpochMilli(Long.parseLong(text));
            } catch (NumberFormatException ignored) {
                throw new RestIngestValidationException("invalid timestamp: " + text, e);
            }
        }
    }

    static long durationMillis(Instant start, Instant end) {
        return Math.max(Duration.between(start, end).toMillis(), 0);
    }

    static String protocolName(Object value) {
        if (value == null) {
            return "unknown";
        }
        if (value instanceof Number number) {
            return protocolNameForNumber(number.intValue());
        }
        String text = value.toString().trim().toLowerCase(Locale.ROOT);
        if (text.isEmpty()) {
            return "unknown";
        }
        try {
            return protocolNameForNumber(Integer.parseInt(text));
        } catch (NumberFormatException ignored) {
            return switch (text) {
                case "icmp" -> "icmp";
                case "tcp" -> "tcp";
                case "udp" -> "udp";
                default -> text;
            };
        }
    }

    private static String protocolNameForNumber(int protocolNumber) {
        return switch (protocolNumber) {
            case 1 -> "icmp";
            case 6 -> "tcp";
            case 17 -> "udp";
            default -> Integer.toString(protocolNumber);
        };
    }

    static int protocolNumber(Object value) {
        if (value == null) {
            return 0;
        }
        if (value instanceof Number number) {
            return number.intValue();
        }
        String text = value.toString().trim().toLowerCase(Locale.ROOT);
        if (text.isEmpty()) {
            return 0;
        }
        try {
            return Integer.parseInt(text);
        } catch (NumberFormatException ignored) {
            return switch (text) {
                case "icmp" -> 1;
                case "tcp" -> 6;
                case "udp" -> 17;
                default -> 0;
            };
        }
    }

    static long longValue(Object value) {
        if (value instanceof BigInteger bigInteger) {
            return bigInteger.longValue();
        }
        if (value instanceof BigDecimal bigDecimal) {
            return bigDecimal.longValue();
        }
        if (value instanceof Number number) {
            return number.longValue();
        }
        return Long.parseLong(value.toString());
    }

    static int intValue(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        return Integer.parseInt(value.toString());
    }
}
