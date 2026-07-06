package com.kien.networkflowcollector.normalization;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.common.IpAddressSupport;
import java.time.Duration;
import java.util.Objects;
import org.springframework.stereotype.Component;

@Component
public class NormalizedFlowValidator {

    private static final int MAX_PORT = 65_535;
    private static final int MAX_TCP_FLAGS = 65_535;
    private static final long MAX_UINT32 = 4_294_967_295L;

    public void validate(NormalizedFlow flow) {
        Objects.requireNonNull(flow, "flow");
        require(flow.flowId() != null, flow, "missing_field", "flowId is required");
        require(flow.tsStart() != null, flow, "missing_field", "tsStart is required");
        require(flow.tsEnd() != null, flow, "missing_field", "tsEnd is required");
        require(flow.sourceType() != null && !flow.sourceType().isBlank(), flow, "missing_field", "sourceType is required");
        require(flow.exporterIp() != null && !flow.exporterIp().isBlank(), flow, "missing_field", "exporterIp is required");
        require(flow.protocol() != null && !flow.protocol().isBlank(), flow, "missing_field", "protocol is required");
        require(IpAddressSupport.isIpLiteral(flow.exporterIp()), flow, "invalid_ip", "exporterIp must be an IP literal");
        require(IpAddressSupport.isIpLiteral(flow.srcIp()), flow, "invalid_ip", "srcIp must be an IP literal");
        require(IpAddressSupport.isIpLiteral(flow.dstIp()), flow, "invalid_ip", "dstIp must be an IP literal");
        require(flow.srcPort() >= 0 && flow.srcPort() <= MAX_PORT, flow, "invalid_port", "srcPort is out of range");
        require(flow.dstPort() >= 0 && flow.dstPort() <= MAX_PORT, flow, "invalid_port", "dstPort is out of range");
        require(flow.bytesTotal() >= 0, flow, "invalid_counter", "bytesTotal is out of range");
        require(flow.packetsTotal() >= 0, flow, "invalid_counter", "packetsTotal is out of range");
        require(!flow.tsStart().isAfter(flow.tsEnd()), flow, "invalid_timestamp", "tsStart must be before or equal to tsEnd");

        long expectedDurationMs = Duration.between(flow.tsStart(), flow.tsEnd()).toMillis();
        require(
                flow.durationMs() == expectedDurationMs,
                flow,
                "invalid_duration",
                "durationMs must match tsStart and tsEnd");

        if (flow.tcpFlags() != null) {
            require(flow.tcpFlags() >= 0 && flow.tcpFlags() <= MAX_TCP_FLAGS, flow, "invalid_tcp_flags", "tcpFlags is out of range");
            require("tcp".equalsIgnoreCase(flow.protocol()), flow, "invalid_tcp_flags", "tcpFlags is only valid for TCP flows");
        }

        if (flow.sampled()) {
            require(
                    flow.samplingRate() != null && flow.samplingRate() > 0,
                    flow,
                    "invalid_sampling",
                    "sampled flows require samplingRate > 0");
        } else {
            require(flow.samplingRate() == null, flow, "invalid_sampling", "unsampled flows must not set samplingRate");
            require(flow.samplePool() == null, flow, "invalid_sampling", "unsampled flows must not set samplePool");
        }

        validateCountryCode(flow.srcCountryCode(), flow, "srcCountryCode");
        validateCountryCode(flow.dstCountryCode(), flow, "dstCountryCode");
        validateAsn(flow.srcAsn(), flow, "srcAsn");
        validateAsn(flow.dstAsn(), flow, "dstAsn");
    }

    private static void validateCountryCode(String countryCode, NormalizedFlow flow, String fieldName) {
        if (countryCode == null) {
            return;
        }
        require(
                countryCode.length() == 2
                        && Character.isUpperCase(countryCode.charAt(0))
                        && Character.isUpperCase(countryCode.charAt(1)),
                flow,
                "invalid_enrichment",
                fieldName + " must be an uppercase ISO-3166 alpha-2 code");
    }

    private static void validateAsn(Long asn, NormalizedFlow flow, String fieldName) {
        if (asn == null) {
            return;
        }
        require(asn >= 0 && asn <= MAX_UINT32, flow, "invalid_enrichment", fieldName + " must fit UInt32");
    }

    private static void require(boolean condition, NormalizedFlow flow, String reason, String message) {
        if (!condition) {
            throw new FlowValidationException(flow.sourceType(), reason, message);
        }
    }
}
