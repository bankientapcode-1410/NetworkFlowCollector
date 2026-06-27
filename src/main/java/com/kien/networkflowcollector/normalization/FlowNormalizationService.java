package com.kien.networkflowcollector.normalization;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.util.List;
import java.util.Objects;
import org.springframework.stereotype.Service;

@Service
public class FlowNormalizationService {

    private final NormalizerRegistry registry;
    private final NormalizedFlowValidator validator;

    public FlowNormalizationService(NormalizerRegistry registry, NormalizedFlowValidator validator) {
        this.registry = Objects.requireNonNull(registry, "registry");
        this.validator = Objects.requireNonNull(validator, "validator");
    }

    public NormalizedFlow normalize(RawFlowRecord raw) {
        Objects.requireNonNull(raw, "raw");
        if (!registry.ready()) {
            throw new NormalizationServiceNotReadyException(registry.coverage());
        }
        NormalizedFlow flow = registry.normalize(raw);
        validator.validate(flow);
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
}
