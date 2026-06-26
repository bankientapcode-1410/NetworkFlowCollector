package com.kien.networkflowcollector.collectors.zeek;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.time.Instant;
import java.util.Locale;

final class ZeekProtocol {

    static final String COLLECTOR_TYPE = "zeek";
    static final String CONN_SOURCE_TYPE = "zeek-conn";
    static final String CONN_PATH = "conn";
    static final String DEFAULT_EXPORTER_IP = "zeek";

    private ZeekProtocol() {}

    static Instant timestamp(Object value) {
        if (value instanceof Instant instant) {
            return instant;
        }
        BigDecimal seconds = decimal(value);
        BigInteger epochSecond = seconds.toBigInteger();
        BigDecimal fractional = seconds.subtract(new BigDecimal(epochSecond));
        int nanos =
                fractional
                        .movePointRight(9)
                        .setScale(0, RoundingMode.HALF_UP)
                        .intValue();
        if (nanos == 1_000_000_000) {
            return Instant.ofEpochSecond(epochSecond.longValue() + 1);
        }
        return Instant.ofEpochSecond(epochSecond.longValue(), nanos);
    }

    static long intervalMillis(Object value) {
        return decimal(value).movePointRight(3).setScale(0, RoundingMode.HALF_UP).longValue();
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
