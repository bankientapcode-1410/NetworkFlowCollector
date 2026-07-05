package com.kien.networkflowcollector.plugins.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kien.networkflowcollector.kafka.PublishBackpressureException;
import com.kien.networkflowcollector.spi.CollectorConfig;
import com.kien.networkflowcollector.spi.CollectorStatus;
import com.kien.networkflowcollector.spi.FlowCollector;
import com.kien.networkflowcollector.spi.FlowNormalizer;
import com.kien.networkflowcollector.spi.FlowPublisher;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;

class RestFlowCollectorTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void collectorAdvertisesRestSupport() {
        RestFlowCollector collector = new RestFlowCollector();

        assertThat(collector.type()).isEqualTo("rest");
        assertThat(collector.supportedSourceTypes()).containsExactly("rest");
    }

    @Test
    void serviceLoaderDiscoversRestCollectorAndNormalizer() {
        assertThat(ServiceLoader.load(FlowCollector.class).stream().map(ServiceLoader.Provider::type))
                .contains(RestFlowCollector.class);
        assertThat(ServiceLoader.load(FlowNormalizer.class).stream().map(ServiceLoader.Provider::type))
                .contains(RestFlowNormalizer.class);
    }

    @Test
    void publishesSingleRecordAfterValidation() throws Exception {
        InMemoryPublisher publisher = new InMemoryPublisher();
        RestFlowCollector collector = startedCollector(publisher, 5);

        RestIngestReceipt receipt = collector.ingest(json(validPayload()));

        assertThat(receipt.acceptedRecords()).isEqualTo(1);
        assertThat(publisher.records()).hasSize(1);
        RawFlowRecord record = publisher.records().getFirst();
        assertThat(record.sourceType()).isEqualTo("rest");
        assertThat(record.exporterIp()).isEqualTo("127.0.0.1");
        assertThat(record.receivedAt()).isEqualTo(Instant.parse("2024-01-01T00:00:00Z"));
        assertThat(record.fields()).containsEntry("src_ip", "192.168.2.10");
        assertThat(record.fields()).containsKeys("rest_batch_id", "rest_batch_index");
        assertThat(collector.health().status()).isEqualTo(CollectorStatus.UP);
    }

    @Test
    void rejectsInvalidBatchBeforePublishingAnyRecord() throws Exception {
        InMemoryPublisher publisher = new InMemoryPublisher();
        RestFlowCollector collector = startedCollector(publisher, 5);
        String invalidBatch = "[" + validPayload() + "," + validPayload().replace("\"fields\"", "\"extra\"") + "]";

        assertThatThrownBy(() -> collector.ingest(json(invalidBatch)))
                .isInstanceOf(RestIngestValidationException.class)
                .hasMessageContaining("not a recognized field");

        assertThat(publisher.records()).isEmpty();
        assertThat(collector.health().status()).isEqualTo(CollectorStatus.DEGRADED);
    }

    @Test
    void rejectsBatchOverConfiguredLimit() throws Exception {
        RestFlowCollector collector = startedCollector(new InMemoryPublisher(), 1);
        String oversizedBatch = "[" + validPayload() + "," + validPayload() + "]";

        assertThatThrownBy(() -> collector.ingest(json(oversizedBatch)))
                .isInstanceOf(RestIngestValidationException.class)
                .hasMessageContaining("exceeds max_batch_size 1");
    }

    @Test
    void mapsPublisherBackpressureToRestException() throws Exception {
        RestFlowCollector collector =
                startedCollector(
                        record ->
                                CompletableFuture.failedFuture(
                                        new PublishBackpressureException("no permits")), 5);

        assertThatThrownBy(() -> collector.ingest(json(validPayload())))
                .isInstanceOf(RestIngestBackpressureException.class);
        assertThat(collector.health().status()).isEqualTo(CollectorStatus.DEGRADED);
    }

    private RestFlowCollector startedCollector(FlowPublisher publisher, int maxBatchSize) {
        RestFlowCollector collector = new RestFlowCollector();
        collector.init(new CollectorConfig(true, Map.of("maxBatchSize", maxBatchSize)), publisher);
        collector.start();
        return collector;
    }

    private JsonNode json(String text) throws Exception {
        return objectMapper.readTree(text);
    }

    private static String validPayload() {
        return """
                {
                  "sourceType": "rest",
                  "exporterIp": "127.0.0.1",
                  "receivedAt": "2024-01-01T00:00:00Z",
                  "fields": {
                    "event_id": "rest-event-1",
                    "src_ip": "192.168.2.10",
                    "dst_ip": "10.1.0.20",
                    "src_port": 52000,
                    "dst_port": 443,
                    "protocol": "TCP",
                    "bytes": 9000,
                    "packets": 30,
                    "tcp_flags": "0x1b",
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
