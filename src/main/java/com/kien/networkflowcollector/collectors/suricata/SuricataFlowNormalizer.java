package com.kien.networkflowcollector.collectors.suricata;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.spi.FlowNormalizer;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import org.springframework.stereotype.Component;

@Component
public class SuricataFlowNormalizer implements FlowNormalizer {

    @Override
    public String sourceType() {
        return SuricataProtocol.FLOW_SOURCE_TYPE;
    }

    @Override
    public NormalizedFlow normalize(RawFlowRecord raw) {
        return SuricataNormalizerSupport.normalizeFlowRecord(raw);
    }
}
