package com.kien.networkflowcollector.storage;

import java.time.Instant;

public record FlowQuery(
        Instant from,
        Instant to,
        String srcIp,
        Integer srcPort,
        String dstIp,
        Integer dstPort,
        String protocol,
        String sourceType,
        int limit) {

    public FlowQuery(
            Instant from,
            Instant to,
            String srcIp,
            String dstIp,
            String protocol,
            String sourceType,
            int limit) {
        this(from, to, srcIp, null, dstIp, null, protocol, sourceType, limit);
    }
}
