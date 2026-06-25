package com.kien.networkflowcollector.collectors.netflow.v5;

import java.time.Instant;

final class NetFlowV5Protocol {

    static final String SOURCE_TYPE = "netflow-v5";
    static final int VERSION = 5;
    static final int HEADER_LENGTH = 24;
    static final int RECORD_LENGTH = 48;
    static final int MAX_RECORDS = 30;

    private static final long UINT32_MODULUS = 1L << 32;

    private NetFlowV5Protocol() {}

    static String ipv4(long value) {
        return ((value >>> 24) & 0xff)
                + "."
                + ((value >>> 16) & 0xff)
                + "."
                + ((value >>> 8) & 0xff)
                + "."
                + (value & 0xff);
    }

    static Instant exportTime(long unixSeconds, long unixNanos) {
        return Instant.ofEpochSecond(unixSeconds, unixNanos);
    }

    static Instant switchedTime(Instant exportTime, long sysUptimeMillis, long switchedMillis) {
        return exportTime.minusMillis(unsignedMillisSince(sysUptimeMillis, switchedMillis));
    }

    static long durationMillis(long firstSwitchedMillis, long lastSwitchedMillis) {
        return unsignedMillisSince(lastSwitchedMillis, firstSwitchedMillis);
    }

    static String protocolName(int protocolNumber) {
        return switch (protocolNumber) {
            case 1 -> "icmp";
            case 6 -> "tcp";
            case 17 -> "udp";
            case 47 -> "gre";
            case 50 -> "esp";
            case 58 -> "ipv6-icmp";
            default -> "ip-" + protocolNumber;
        };
    }

    private static long unsignedMillisSince(long laterMillis, long earlierMillis) {
        if (laterMillis >= earlierMillis) {
            return laterMillis - earlierMillis;
        }
        return UINT32_MODULUS - earlierMillis + laterMillis;
    }
}
