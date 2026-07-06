package com.kien.networkflowcollector.enrichment;

import java.util.Optional;

@FunctionalInterface
public interface FlowEnrichmentProvider {

    Optional<IpEnrichment> lookup(String ipAddress);

    static FlowEnrichmentProvider noop() {
        return ignored -> Optional.empty();
    }
}
