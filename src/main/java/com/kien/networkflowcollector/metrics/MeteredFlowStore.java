package com.kien.networkflowcollector.metrics;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.storage.AggBucket;
import com.kien.networkflowcollector.storage.AggQuery;
import com.kien.networkflowcollector.storage.FlowCursor;
import com.kien.networkflowcollector.storage.FlowQuery;
import com.kien.networkflowcollector.storage.FlowSlice;
import com.kien.networkflowcollector.storage.FlowStore;
import com.kien.networkflowcollector.storage.WriteReceipt;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

public class MeteredFlowStore implements FlowStore {

    private final FlowStore delegate;
    private final PipelineMetrics metrics;

    public MeteredFlowStore(FlowStore delegate, PipelineMetrics metrics) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.metrics = Objects.requireNonNull(metrics, "metrics");
    }

    @Override
    public WriteReceipt batchInsert(List<NormalizedFlow> flows) {
        WriteReceipt receipt = delegate.batchInsert(flows);
        metrics.recordStored(receipt.recordsWritten());
        return receipt;
    }

    @Override
    public FlowSlice<NormalizedFlow> query(FlowQuery filter, FlowCursor cursor) {
        return delegate.query(filter, cursor);
    }

    @Override
    public Optional<NormalizedFlow> findById(UUID flowId) {
        return delegate.findById(flowId);
    }

    @Override
    public List<AggBucket> topTalkers(AggQuery query) {
        return delegate.topTalkers(query);
    }

    @Override
    public List<AggBucket> topPorts(AggQuery query) {
        return delegate.topPorts(query);
    }
}
