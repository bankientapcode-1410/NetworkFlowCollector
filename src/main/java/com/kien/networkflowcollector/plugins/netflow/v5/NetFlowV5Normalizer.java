package com.kien.networkflowcollector.plugins.netflow.v5;

import com.kien.networkflowcollector.plugins.netflow.NetFlowNormalizerSupport;
import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.spi.FlowNormalizer;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import org.springframework.stereotype.Component;

@Component
public class NetFlowV5Normalizer implements FlowNormalizer {

    @Override
    public String sourceType() {
        return NetFlowV5Protocol.SOURCE_TYPE;
    }

    @Override
    public NormalizedFlow normalize(RawFlowRecord raw) {
        return NetFlowNormalizerSupport.normalizeFixedRecord(
                raw, NetFlowV5Protocol.SOURCE_TYPE, "NetFlow v5");
    }
}
