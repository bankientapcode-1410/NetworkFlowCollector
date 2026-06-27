package com.kien.networkflowcollector.normalization;

import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

@Component("normalizerCoverage")
public class NormalizerCoverageHealthIndicator implements HealthIndicator {

    private final NormalizerRegistry registry;

    public NormalizerCoverageHealthIndicator(NormalizerRegistry registry) {
        this.registry = registry;
    }

    @Override
    public Health health() {
        NormalizerCoverage coverage = registry.coverage();
        Health.Builder builder = coverage.complete() ? Health.up() : Health.down();
        return builder
                .withDetail("requiredSourceTypes", coverage.requiredSourceTypes())
                .withDetail("availableSourceTypes", coverage.availableSourceTypes())
                .withDetail("missingSourceTypes", coverage.missingSourceTypes())
                .build();
    }
}
