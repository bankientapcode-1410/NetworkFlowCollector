package com.kien.networkflowcollector.storage;

import java.time.Instant;

public record FlowQuery(
        Instant from,
        Instant to,
        String srcIp,
        String dstIp,
        String protocol,
        String sourceType,
        int limit) {}
