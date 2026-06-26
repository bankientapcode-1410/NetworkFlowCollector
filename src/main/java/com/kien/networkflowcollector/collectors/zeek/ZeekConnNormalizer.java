package com.kien.networkflowcollector.collectors.zeek;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.spi.FlowNormalizer;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import org.springframework.stereotype.Component;

@Component
public class ZeekConnNormalizer implements FlowNormalizer {

    @Override
    public String sourceType() {
        return ZeekProtocol.CONN_SOURCE_TYPE;
    }

    @Override
    public NormalizedFlow normalize(RawFlowRecord raw) {
        return ZeekNormalizerSupport.normalizeConnRecord(raw);
    }
}
