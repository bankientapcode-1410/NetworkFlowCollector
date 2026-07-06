package com.kien.networkflowcollector.normalization;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.enrichment.FlowEnrichmentProvider;
import com.kien.networkflowcollector.enrichment.IpEnrichment;
import com.kien.networkflowcollector.metrics.PipelineMetrics;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class FlowNormalizationService {

    private final NormalizerRegistry registry;
    private final NormalizedFlowValidator validator;
    private final FlowEnrichmentProvider enrichmentProvider;
    private final PipelineMetrics metrics;

    @Autowired
    public FlowNormalizationService(
            NormalizerRegistry registry,
            NormalizedFlowValidator validator,
            FlowEnrichmentProvider enrichmentProvider,
            PipelineMetrics metrics) {
        this.registry = Objects.requireNonNull(registry, "registry");
        this.validator = Objects.requireNonNull(validator, "validator");
        this.enrichmentProvider = Objects.requireNonNull(enrichmentProvider, "enrichmentProvider");
        this.metrics = Objects.requireNonNull(metrics, "metrics");
    }

    FlowNormalizationService(NormalizerRegistry registry, NormalizedFlowValidator validator) {
        this(registry, validator, FlowEnrichmentProvider.noop(), PipelineMetrics.unregistered());
    }

    public NormalizedFlow normalize(RawFlowRecord raw) {
        Objects.requireNonNull(raw, "raw");
        if (!registry.ready()) {
            throw new NormalizationServiceNotReadyException(registry.coverage());
        }
        NormalizedFlow flow = enrich(registry.normalize(raw));
        validator.validate(flow);
        metrics.recordNormalized();
        return flow;
    }

    public List<NormalizedFlow> normalizeAll(List<RawFlowRecord> records) {
        Objects.requireNonNull(records, "records");
        return records.stream().map(this::normalize).toList();
    }

    public boolean ready() {
        return registry.ready();
    }

    public NormalizerCoverage coverage() {
        return registry.coverage();
    }

    private NormalizedFlow enrich(NormalizedFlow flow) {
        Optional<IpEnrichment> src = enrichmentProvider.lookup(flow.srcIp());
        Optional<IpEnrichment> dst = enrichmentProvider.lookup(flow.dstIp());
        if (src.isEmpty() && dst.isEmpty()) {
            return flow;
        }

        return flow.withEnrichment(
                firstNonBlank(flow.srcCountryCode(), src.map(IpEnrichment::countryCode).orElse(null)),
                firstNonNull(flow.srcAsn(), src.map(IpEnrichment::asn).orElse(null)),
                firstNonBlank(flow.srcAsOrg(), src.map(IpEnrichment::asOrg).orElse(null)),
                firstNonBlank(flow.dstCountryCode(), dst.map(IpEnrichment::countryCode).orElse(null)),
                firstNonNull(flow.dstAsn(), dst.map(IpEnrichment::asn).orElse(null)),
                firstNonBlank(flow.dstAsOrg(), dst.map(IpEnrichment::asOrg).orElse(null)));
    }

    private static String firstNonBlank(String primary, String fallback) {
        if (primary != null && !primary.isBlank()) {
            return primary;
        }
        return fallback == null || fallback.isBlank() ? null : fallback;
    }

    private static Long firstNonNull(Long primary, Long fallback) {
        return primary == null ? fallback : primary;
    }
}
