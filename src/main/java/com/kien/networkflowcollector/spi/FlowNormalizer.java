package com.kien.networkflowcollector.spi;

import com.kien.networkflowcollector.common.NormalizedFlow;

public interface FlowNormalizer {

    String sourceType();

    NormalizedFlow normalize(RawFlowRecord raw);
}
