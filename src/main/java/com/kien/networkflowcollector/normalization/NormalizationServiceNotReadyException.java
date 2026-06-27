package com.kien.networkflowcollector.normalization;

public class NormalizationServiceNotReadyException extends RuntimeException {

    private final NormalizerCoverage coverage;

    public NormalizationServiceNotReadyException(NormalizerCoverage coverage) {
        super("Normalizer coverage is incomplete; missing source types: " + coverage.missingSourceTypes());
        this.coverage = coverage;
    }

    public NormalizerCoverage coverage() {
        return coverage;
    }
}
