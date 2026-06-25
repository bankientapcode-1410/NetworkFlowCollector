package com.kien.networkflowcollector.collectors.netflow.ipfix;

import com.kien.networkflowcollector.collectors.netflow.NetFlowNormalizerSupport;
import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.spi.FlowNormalizer;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import org.springframework.stereotype.Component;

@Component
public class IpfixNormalizer implements FlowNormalizer {

    @Override
    public String sourceType() {
        return IpfixProtocol.SOURCE_TYPE;
    }

    @Override
    public NormalizedFlow normalize(RawFlowRecord raw) {
        return NetFlowNormalizerSupport.normalizeFlexibleRecord(raw, IpfixProtocol.SOURCE_TYPE);
    }
}
