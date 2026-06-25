package com.kien.networkflowcollector.collectors.netflow.v9;

import com.kien.networkflowcollector.collectors.netflow.NetFlowNormalizerSupport;
import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.spi.FlowNormalizer;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import org.springframework.stereotype.Component;

@Component
public class NetFlowV9Normalizer implements FlowNormalizer {

    @Override
    public String sourceType() {
        return NetFlowV9Protocol.SOURCE_TYPE;
    }

    @Override
    public NormalizedFlow normalize(RawFlowRecord raw) {
        return NetFlowNormalizerSupport.normalizeFlexibleRecord(raw, NetFlowV9Protocol.SOURCE_TYPE);
    }
}
