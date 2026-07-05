package com.kien.networkflowcollector.metrics;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.storage.AggBucket;
import com.kien.networkflowcollector.storage.AggQuery;
import com.kien.networkflowcollector.storage.FlowCursor;
import com.kien.networkflowcollector.storage.FlowQuery;
import com.kien.networkflowcollector.storage.FlowSlice;
import com.kien.networkflowcollector.storage.FlowStore;
import com.kien.networkflowcollector.storage.WriteReceipt;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("MeteredFlowStore")
class MeteredFlowStoreTest {

    @Test
    @DisplayName("successful batch insert records database writes")
    void batchInsert_recordsWrittenRows() {
        FlowStore delegate = new StubFlowStore();
        PipelineMetrics metrics = PipelineMetrics.unregistered();
        MeteredFlowStore store = new MeteredFlowStore(delegate, metrics);
        NormalizedFlow flow = mock(NormalizedFlow.class);
        when(flow.flowId()).thenReturn(UUID.randomUUID());

        WriteReceipt receipt = store.batchInsert(List.of(flow, flow));

        PipelineMetricsSnapshot snapshot = metrics.snapshot();
        assertThat(receipt.recordsWritten()).isEqualTo(2);
        assertThat(snapshot.storedTotal()).isEqualTo(2);
    }

    private static final class StubFlowStore implements FlowStore {

        @Override
        public WriteReceipt batchInsert(List<NormalizedFlow> flows) {
            return new WriteReceipt(flows.size(), Instant.now());
        }

        @Override
        public FlowSlice<NormalizedFlow> query(FlowQuery filter, FlowCursor cursor) {
            return new FlowSlice<>(List.of(), Optional.empty(), false);
        }

        @Override
        public Optional<NormalizedFlow> findById(UUID flowId) {
            return Optional.empty();
        }

        @Override
        public List<AggBucket> topTalkers(AggQuery query) {
            return List.of();
        }

        @Override
        public List<AggBucket> topPorts(AggQuery query) {
            return List.of();
        }
    }
}
