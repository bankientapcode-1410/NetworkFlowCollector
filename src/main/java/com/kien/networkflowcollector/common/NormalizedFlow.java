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
        Instant ingestTime) {}
