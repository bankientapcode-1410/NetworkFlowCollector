package com.kien.networkflowcollector.plugins.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.kien.networkflowcollector.collector.CollectorProperties;
import com.kien.networkflowcollector.collector.CollectorRegistry;
import com.kien.networkflowcollector.spi.FlowPublisher;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class RestIngestControllerTest {

    private CollectorRegistry registry;

    @AfterEach
    void stopRegistry() {
        if (registry != null) {
            registry.stop();
        }
    }

    @Test
    void postIngestReturnsAcceptedAfterPublishing() throws Exception {
        InMemoryPublisher publisher = new InMemoryPublisher();
        MockMvc mockMvc = mockMvc(publisher, 5);

        mockMvc.perform(post("/ingest").contentType(MediaType.APPLICATION_JSON).content(validPayload()))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.batchId").isNotEmpty())
                .andExpect(jsonPath("$.acceptedRecords").value(1));

        assertThat(publisher.records()).hasSize(1);
        assertThat(publisher.records().getFirst().sourceType()).isEqualTo("rest");
    }

    @Test
    void postIngestValidationFailureReturns422AndPublishesNothing() throws Exception {
        InMemoryPublisher publisher = new InMemoryPublisher();
        MockMvc mockMvc = mockMvc(publisher, 5);

        mockMvc.perform(
                        post("/ingest")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(validPayload().replace("\"src_ip\"", "\"unexpected\"")))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value("validation_failed"));

        assertThat(publisher.records()).isEmpty();
    }

    private MockMvc mockMvc(FlowPublisher publisher, int maxBatchSize) {
        CollectorProperties properties = new CollectorProperties();
        CollectorProperties.CollectorSpec spec = new CollectorProperties.CollectorSpec();
        spec.setEnabled(true);
        spec.setProperties(Map.of("maxBatchSize", maxBatchSize));
        properties.getConfigs().put("rest", spec);

        registry = new CollectorRegistry(properties, publisherProvider(publisher));
        registry.start();
        return MockMvcBuilders.standaloneSetup(new RestIngestController(registry)).build();
    }

    private static ObjectProvider<FlowPublisher> publisherProvider(FlowPublisher publisher) {
        return new ObjectProvider<>() {
            @Override
            public FlowPublisher getObject() {
                return publisher;
            }

            @Override
            public FlowPublisher getIfAvailable() {
                return publisher;
            }
        };
    }

    private static String validPayload() {
        return """
                {
                  "source_type": "rest",
                  "exporter_ip": "127.0.0.1",
                  "fields": {
                    "event_id": "rest-event-1",
                    "src_ip": "192.168.2.10",
                    "dst_ip": "10.1.0.20",
                    "src_port": 52000,
                    "dst_port": 443,
                    "protocol": "TCP",
                    "bytes": 9000,
                    "packets": 30,
                    "tcp_flags": 27,
                    "ts_start": "2026-07-05T07:59:58Z",
                    "ts_end": "2026-07-05T08:00:00Z"
                  }
                }
                """;
    }

    private static final class InMemoryPublisher implements FlowPublisher {

        private final CopyOnWriteArrayList<RawFlowRecord> records = new CopyOnWriteArrayList<>();

        @Override
        public CompletionStage<Void> publish(RawFlowRecord record) {
            records.add(record);
            return CompletableFuture.completedFuture(null);
        }

        List<RawFlowRecord> records() {
            return List.copyOf(records);
        }
    }
}
