package com.kien.networkflowcollector.common;

import java.time.Instant;
import java.util.UUID;

public record NormalizedFlow(
        UUID flowId,
        Instant tsStart,
        Instant tsEnd,
        long durationMs,
        String srcIp,
        int srcPort,
        String dstIp,
        int dstPort,
        String protocol,
        long bytesTotal,
        long packetsTotal,
        Integer tcpFlags,
        boolean sampled,
        Long samplingRate,
        Long samplePool,
        String sourceType,
        String exporterIp,
        String srcCountryCode,
        Long srcAsn,
        String srcAsOrg,
        String dstCountryCode,
        Long dstAsn,
        String dstAsOrg,
        Instant ingestTime) {

    public NormalizedFlow withEnrichment(
            String srcCountryCode,
            Long srcAsn,
            String srcAsOrg,
            String dstCountryCode,
            Long dstAsn,
            String dstAsOrg) {
        return new NormalizedFlow(
                flowId,
                tsStart,
                tsEnd,
                durationMs,
                srcIp,
                srcPort,
                dstIp,
                dstPort,
                protocol,
                bytesTotal,
                packetsTotal,
                tcpFlags,
                sampled,
                samplingRate,
                samplePool,
                sourceType,
                exporterIp,
                srcCountryCode,
                srcAsn,
                srcAsOrg,
                dstCountryCode,
                dstAsn,
                dstAsOrg,
                ingestTime);
    }
}
