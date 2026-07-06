package com.kien.networkflowcollector.enrichment;

import com.kien.networkflowcollector.common.IpAddressSupport;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

public final class PrefixFlowEnrichmentProvider implements FlowEnrichmentProvider {

    public static final String DEFAULT_PREFIXES =
            "1.1.1.0/24,AU,13335,Cloudflare Inc;"
                    + "8.8.8.0/24,US,15169,Google LLC;"
                    + "9.9.9.0/24,CH,19281,Quad9;"
                    + "17.0.0.0/8,US,714,Apple Inc;"
                    + "93.184.216.0/24,US,15133,Edgecast Inc;"
                    + "104.16.0.0/12,US,13335,Cloudflare Inc;"
                    + "142.250.0.0/15,US,15169,Google LLC;"
                    + "208.67.222.0/24,US,36692,Cisco OpenDNS";

    private final List<Entry> entries;

    private PrefixFlowEnrichmentProvider(List<Entry> entries) {
        this.entries = entries.stream()
                .sorted(Comparator.comparingInt(Entry::prefixLength).reversed())
                .toList();
    }

    public static PrefixFlowEnrichmentProvider fromSpec(String spec) {
        if (spec == null || spec.isBlank()) {
            return new PrefixFlowEnrichmentProvider(List.of());
        }

        List<Entry> entries = new ArrayList<>();
        for (String rawEntry : spec.split(";")) {
            String entry = rawEntry.trim();
            if (!entry.isEmpty()) {
                entries.add(parseEntry(entry));
            }
        }
        return new PrefixFlowEnrichmentProvider(entries);
    }

    @Override
    public Optional<IpEnrichment> lookup(String ipAddress) {
        if (!IpAddressSupport.isIpLiteral(ipAddress)) {
            return Optional.empty();
        }
        InetAddress address = parseAddress(ipAddress);
        for (Entry entry : entries) {
            if (entry.block().contains(address)) {
                return Optional.of(entry.enrichment());
            }
        }
        return Optional.empty();
    }

    private static Entry parseEntry(String rawEntry) {
        String[] parts = rawEntry.split(",", 4);
        if (parts.length < 2) {
            throw new IllegalArgumentException(
                    "Enrichment prefix entries must use cidr,country[,asn[,as_org]]: " + rawEntry);
        }

        CidrBlock block = CidrBlock.parse(parts[0].trim());
        String countryCode = countryCode(parts[1]);
        Long asn = parts.length >= 3 ? asn(parts[2]) : null;
        String asOrg = parts.length >= 4 ? blankToNull(parts[3]) : null;
        return new Entry(block, new IpEnrichment(countryCode, asn, asOrg));
    }

    private static String countryCode(String value) {
        String countryCode = blankToNull(value);
        if (countryCode == null) {
            return null;
        }
        countryCode = countryCode.toUpperCase(Locale.ROOT);
        if (countryCode.length() != 2
                || !Character.isLetter(countryCode.charAt(0))
                || !Character.isLetter(countryCode.charAt(1))) {
            throw new IllegalArgumentException("country code must be ISO-3166 alpha-2: " + value);
        }
        return countryCode;
    }

    private static Long asn(String value) {
        String text = blankToNull(value);
        if (text == null) {
            return null;
        }
        long parsed = Long.parseLong(text);
        if (parsed < 0 || parsed > 4_294_967_295L) {
            throw new IllegalArgumentException("ASN must fit UInt32: " + value);
        }
        return parsed;
    }

    private static String blankToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static InetAddress parseAddress(String value) {
        try {
            return InetAddress.getByName(value);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Invalid IP address: " + value, e);
        }
    }

    private record Entry(CidrBlock block, IpEnrichment enrichment) {

        private int prefixLength() {
            return block.prefixLength();
        }
    }

    private record CidrBlock(byte[] network, int prefixLength) {

        private CidrBlock {
            network = Objects.requireNonNull(network, "network").clone();
            if (prefixLength < 0 || prefixLength > network.length * Byte.SIZE) {
                throw new IllegalArgumentException("prefixLength is out of range");
            }
        }

        static CidrBlock parse(String value) {
            String text = Objects.requireNonNull(value, "value").trim();
            String addressText = text;
            Integer prefixLength = null;
            int slash = text.indexOf('/');
            if (slash >= 0) {
                if (slash == 0 || slash != text.lastIndexOf('/') || slash == text.length() - 1) {
                    throw new IllegalArgumentException("Invalid CIDR: " + value);
                }
                addressText = text.substring(0, slash);
                prefixLength = Integer.parseInt(text.substring(slash + 1));
            }
            if (!IpAddressSupport.isIpLiteral(addressText)) {
                throw new IllegalArgumentException("CIDR address must be an IP literal: " + value);
            }

            byte[] address = parseAddress(addressText).getAddress();
            int maxPrefixLength = address.length * Byte.SIZE;
            int effectivePrefixLength = prefixLength == null ? maxPrefixLength : prefixLength;
            if (effectivePrefixLength < 0 || effectivePrefixLength > maxPrefixLength) {
                throw new IllegalArgumentException("CIDR prefix is out of range: " + value);
            }
            return new CidrBlock(mask(address, effectivePrefixLength), effectivePrefixLength);
        }

        boolean contains(InetAddress address) {
            byte[] candidate = address.getAddress();
            if (candidate.length != network.length) {
                return false;
            }

            int remainingBits = prefixLength;
            for (int index = 0; index < network.length && remainingBits > 0; index++) {
                int bits = Math.min(Byte.SIZE, remainingBits);
                int mask = (0xFF << (Byte.SIZE - bits)) & 0xFF;
                if (((candidate[index] & 0xFF) & mask) != ((network[index] & 0xFF) & mask)) {
                    return false;
                }
                remainingBits -= bits;
            }
            return true;
        }

        private static byte[] mask(byte[] address, int prefixLength) {
            byte[] masked = address.clone();
            int fullBytes = prefixLength / Byte.SIZE;
            int remainingBits = prefixLength % Byte.SIZE;
            int clearFrom = fullBytes;
            if (remainingBits > 0) {
                int mask = 0xFF << (Byte.SIZE - remainingBits);
                masked[fullBytes] = (byte) (masked[fullBytes] & mask);
                clearFrom++;
            }
            for (int index = clearFrom; index < masked.length; index++) {
                masked[index] = 0;
            }
            return masked;
        }
    }
}
