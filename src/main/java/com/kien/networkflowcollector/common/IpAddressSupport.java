package com.kien.networkflowcollector.common;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

public final class IpAddressSupport {

    private static final int IPV4_PREFIX_BITS = 32;
    private static final int IPV6_PREFIX_BITS = 128;

    private IpAddressSupport() {}

    public static boolean isIpLiteral(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        if (isIpv4Literal(value)) {
            return true;
        }
        return isIpv6Literal(value);
    }

    public static boolean isCidr(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }

        int slash = value.indexOf('/');
        if (slash <= 0 || slash != value.lastIndexOf('/') || slash == value.length() - 1) {
            return false;
        }

        String address = value.substring(0, slash);
        Integer prefixLength = parsePrefixLength(value.substring(slash + 1));
        if (prefixLength == null) {
            return false;
        }

        if (isIpv4Literal(address)) {
            return prefixLength <= IPV4_PREFIX_BITS;
        }
        if (isIpv6Literal(address)) {
            return prefixLength <= IPV6_PREFIX_BITS;
        }
        return false;
    }

    private static Integer parsePrefixLength(String value) {
        if (value.isEmpty()) {
            return null;
        }
        int prefix = 0;
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (!Character.isDigit(ch)) {
                return null;
            }
            prefix = prefix * 10 + Character.digit(ch, 10);
            if (prefix > IPV6_PREFIX_BITS) {
                return null;
            }
        }
        return prefix;
    }

    private static boolean isIpv4Literal(String value) {
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3) {
                return false;
            }
            for (int i = 0; i < part.length(); i++) {
                if (!Character.isDigit(part.charAt(i))) {
                    return false;
                }
            }
            int octet = Integer.parseInt(part);
            if (octet > 255) {
                return false;
            }
        }
        return true;
    }

    private static boolean isIpv6Literal(String value) {
        if (!value.contains(":")) {
            return false;
        }
        try {
            InetAddress address = InetAddress.getByName(value);
            return address instanceof Inet6Address;
        } catch (UnknownHostException e) {
            return false;
        }
    }
}
