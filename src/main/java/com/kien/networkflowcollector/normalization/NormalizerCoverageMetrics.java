package com.kien.networkflowcollector.normalization;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Component;

@Component
public class NormalizerCoverageMetrics {

    public NormalizerCoverageMetrics(MeterRegistry meterRegistry, NormalizerRegistry registry) {
        Gauge.builder("nfc_normalizer_coverage_missing", registry, value -> value.coverage().missingCount())
                .description("Number of source types in META-INF/nfc/source-types.json without a loaded normalizer")
                .register(meterRegistry);
    }
}
