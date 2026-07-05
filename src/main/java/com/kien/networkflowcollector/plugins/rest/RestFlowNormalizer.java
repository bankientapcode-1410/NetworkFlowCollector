package com.kien.networkflowcollector.plugins.rest;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.spi.FlowNormalizer;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import org.springframework.stereotype.Component;

@Component
public class RestFlowNormalizer implements FlowNormalizer {

    @Override
    public String sourceType() {
        return RestProtocol.SOURCE_TYPE;
    }

    @Override
    public NormalizedFlow normalize(RawFlowRecord raw) {
        return RestFlowNormalizerSupport.normalizeRecord(raw);
    }
}
