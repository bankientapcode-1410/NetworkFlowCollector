package com.kien.networkflowcollector.normalization;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;

public record NormalizerCoverage(
        Set<String> requiredSourceTypes,
        Set<String> availableSourceTypes,
        Set<String> missingSourceTypes) {

    public NormalizerCoverage {
        requiredSourceTypes = sortedCopy(requiredSourceTypes);
        availableSourceTypes = sortedCopy(availableSourceTypes);
        missingSourceTypes = sortedCopy(missingSourceTypes);
    }

    public static NormalizerCoverage of(Collection<String> requiredSourceTypes, Collection<String> availableSourceTypes) {
        Set<String> missing = new TreeSet<>(requiredSourceTypes);
        missing.removeAll(availableSourceTypes);
        return new NormalizerCoverage(Set.copyOf(requiredSourceTypes), Set.copyOf(availableSourceTypes), missing);
    }

    public boolean complete() {
        return missingSourceTypes.isEmpty();
    }

    public int missingCount() {
        return missingSourceTypes.size();
    }

    private static Set<String> sortedCopy(Collection<String> sourceTypes) {
        return Collections.unmodifiableSet(new TreeSet<>(sourceTypes));
    }
}
