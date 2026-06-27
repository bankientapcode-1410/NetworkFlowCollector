package com.kien.networkflowcollector.normalization;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.spi.FlowNormalizer;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.Set;
import org.springframework.stereotype.Component;

@Component
public class NormalizerRegistry {

    private final Map<String, FlowNormalizer> normalizersBySourceType;
    private final NormalizerCoverage coverage;

    public NormalizerRegistry() {
        this(loadFromServiceLoader(), SourceTypeManifest.loadDefault());
    }

    public NormalizerRegistry(Collection<FlowNormalizer> normalizers, Collection<String> requiredSourceTypes) {
        Objects.requireNonNull(normalizers, "normalizers");
        Objects.requireNonNull(requiredSourceTypes, "requiredSourceTypes");

        Map<String, FlowNormalizer> loaded = new LinkedHashMap<>();
        for (FlowNormalizer normalizer : normalizers) {
            String sourceType = sourceType(normalizer);
            FlowNormalizer previous = loaded.putIfAbsent(sourceType, normalizer);
            if (previous != null) {
                throw new NormalizerRegistryException(
                        "Duplicate normalizer for source type "
                                + sourceType
                                + ": "
                                + previous.getClass().getName()
                                + " and "
                                + normalizer.getClass().getName());
            }
        }
        normalizersBySourceType = Map.copyOf(loaded);
        coverage = NormalizerCoverage.of(requiredSourceTypes, normalizersBySourceType.keySet());
    }

    public static NormalizerRegistry fromServiceLoader(Collection<String> requiredSourceTypes) {
        return new NormalizerRegistry(loadFromServiceLoader(), requiredSourceTypes);
    }

    public NormalizedFlow normalize(RawFlowRecord raw) {
        Objects.requireNonNull(raw, "raw");
        return normalizer(raw.sourceType()).normalize(raw);
    }

    public FlowNormalizer normalizer(String sourceType) {
        return findNormalizer(sourceType)
                .orElseThrow(() -> new UnsupportedSourceTypeException(sourceType));
    }

    public Optional<FlowNormalizer> findNormalizer(String sourceType) {
        Objects.requireNonNull(sourceType, "sourceType");
        return Optional.ofNullable(normalizersBySourceType.get(sourceType));
    }

    public boolean supports(String sourceType) {
        return normalizersBySourceType.containsKey(sourceType);
    }

    public boolean ready() {
        return coverage.complete();
    }

    public NormalizerCoverage coverage() {
        return coverage;
    }

    public Set<String> sourceTypes() {
        return normalizersBySourceType.keySet();
    }

    private static Collection<FlowNormalizer> loadFromServiceLoader() {
        return ServiceLoader.load(FlowNormalizer.class).stream()
                .map(ServiceLoader.Provider::get)
                .toList();
    }

    private static String sourceType(FlowNormalizer normalizer) {
        Objects.requireNonNull(normalizer, "normalizer");
        String sourceType = normalizer.sourceType();
        if (sourceType == null || sourceType.isBlank()) {
            throw new NormalizerRegistryException(
                    "Normalizer " + normalizer.getClass().getName() + " returned a blank source type");
        }
        return sourceType;
    }
}
