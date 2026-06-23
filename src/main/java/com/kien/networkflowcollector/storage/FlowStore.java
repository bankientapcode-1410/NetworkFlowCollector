package com.kien.networkflowcollector.storage;

import com.kien.networkflowcollector.common.NormalizedFlow;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface FlowStore {

    WriteReceipt batchInsert(List<NormalizedFlow> flows);

    FlowSlice<NormalizedFlow> query(FlowQuery filter, FlowCursor cursor);

    Optional<NormalizedFlow> findById(UUID flowId);

    List<AggBucket> topTalkers(AggQuery query);

    List<AggBucket> topPorts(AggQuery query);
}
