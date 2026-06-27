package com.kien.networkflowcollector.plugins.netflow;

import io.netty.buffer.ByteBuf;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

public final class NetFlowProtocolSupport {

    private static final long UINT32_MODULUS = 1L << 32;
    private static final long NTP_TO_UNIX_SECONDS = 2_208_988_800L;

    private NetFlowProtocolSupport() {}

    public static String ipv4(long value) {
        return ((value >>> 24) & 0xff)
                + "."
                + ((value >>> 16) & 0xff)
                + "."
                + ((value >>> 8) & 0xff)
                + "."
                + (value & 0xff);
    }

    public static String ipv4(ByteBuf packet, int offset) {
        return ipv4(packet.getUnsignedInt(offset));
    }

    public static String ipv6(ByteBuf packet, int offset) {
        byte[] bytes = new byte[16];
        packet.getBytes(offset, bytes);
        try {
            return InetAddress.getByAddress(bytes).getHostAddress();
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Invalid IPv6 field", e);
        }
    }

    public static Instant exportTime(long unixSeconds, long unixNanos) {
        return Instant.ofEpochSecond(unixSeconds, unixNanos);
    }

    public static Instant exportTimeSeconds(long unixSeconds) {
        return Instant.ofEpochSecond(unixSeconds);
    }

    public static Instant epochMilliseconds(long epochMilliseconds) {
        return Instant.ofEpochMilli(epochMilliseconds);
    }

    public static Instant epochMicroseconds(long epochMicroseconds) {
        long seconds = Math.floorDiv(epochMicroseconds, 1_000_000L);
        long micros = Math.floorMod(epochMicroseconds, 1_000_000L);
        return Instant.ofEpochSecond(seconds, micros * 1_000L);
    }

    public static Instant epochNanoseconds(long epochNanoseconds) {
        long seconds = Math.floorDiv(epochNanoseconds, 1_000_000_000L);
        long nanos = Math.floorMod(epochNanoseconds, 1_000_000_000L);
        return Instant.ofEpochSecond(seconds, nanos);
    }

    public static Instant ntpTimestamp(long seconds, long fraction) {
        long nanos = (fraction * 1_000_000_000L) >>> 32;
        return Instant.ofEpochSecond(seconds - NTP_TO_UNIX_SECONDS, nanos);
    }

    public static Instant switchedTime(Instant exportTime, long sysUptimeMillis, long switchedMillis) {
        return exportTime.minusMillis(unsignedMillisSince(sysUptimeMillis, switchedMillis));
    }

    public static long durationMillis(long firstSwitchedMillis, long lastSwitchedMillis) {
        return unsignedMillisSince(lastSwitchedMillis, firstSwitchedMillis);
    }

    public static long durationMillis(Instant start, Instant end) {
        long duration = Duration.between(start, end).toMillis();
        return Math.max(duration, 0);
    }

    public static String protocolName(int protocolNumber) {
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

    public static long unsignedNumber(ByteBuf packet, int offset, int length) {
        if (length < 0 || length > Long.BYTES) {
            throw new IllegalArgumentException("Unsupported unsigned integer length: " + length);
        }
        long value = 0;
        for (int i = 0; i < length; i++) {
            value = (value << 8) | packet.getUnsignedByte(offset + i);
        }
        return value;
    }

    public static byte[] bytes(ByteBuf packet, int offset, int length) {
        byte[] bytes = new byte[length];
        packet.getBytes(offset, bytes);
        return bytes;
    }

    public static String hex(ByteBuf packet, int offset, int length) {
        StringBuilder out = new StringBuilder(length * 2);
        for (int i = 0; i < length; i++) {
            out.append(String.format("%02x", packet.getUnsignedByte(offset + i)));
        }
        return out.toString();
    }

    public static boolean allZero(ByteBuf packet, int offset, int length) {
        for (int i = 0; i < length; i++) {
            if (packet.getUnsignedByte(offset + i) != 0) {
                return false;
            }
        }
        return true;
    }

    public static void putUnique(Map<String, Object> fields, String key, Object value) {
        if (value == null) {
            return;
        }
        if (!fields.containsKey(key)) {
            fields.put(key, value);
            return;
        }
        int suffix = 2;
        while (fields.containsKey(key + "_" + suffix)) {
            suffix++;
        }
        fields.put(key + "_" + suffix, value);
    }

    private static long unsignedMillisSince(long laterMillis, long earlierMillis) {
        if (laterMillis >= earlierMillis) {
            return laterMillis - earlierMillis;
        }
        return UINT32_MODULUS - earlierMillis + laterMillis;
    }
}
