package com.kien.networkflowcollector.kafka;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.normalization.FlowNormalizationService;
import com.kien.networkflowcollector.normalization.FlowValidationException;
import com.kien.networkflowcollector.normalization.NormalizationServiceNotReadyException;
import com.kien.networkflowcollector.normalization.NormalizerCoverage;
import com.kien.networkflowcollector.normalization.UnsupportedSourceTypeException;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import com.kien.networkflowcollector.storage.FlowStore;
import com.kien.networkflowcollector.storage.WriteReceipt;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.common.TopicPartition;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("KafkaFlowConsumer")
class KafkaFlowConsumerTest {

    @SuppressWarnings("unchecked")
    private final Consumer<String, String> kafkaConsumer = mock(Consumer.class);
    private final RawFlowRecordJsonCodec codec = mock(RawFlowRecordJsonCodec.class);
    private final FlowNormalizationService normalizationService = mock(FlowNormalizationService.class);
    private final FlowStore flowStore = mock(FlowStore.class);
    private final KafkaDeadLetterPublisher dlqPublisher = mock(KafkaDeadLetterPublisher.class);

    private KafkaFlowProperties properties;
    private KafkaFlowConsumer consumer;

    private static final String RAW_TOPIC = "raw-flows";
    private static final TopicPartition TP0 = new TopicPartition(RAW_TOPIC, 0);

    @BeforeEach
    void setUp() {
        properties = new KafkaFlowProperties();
        properties.setRawTopic(RAW_TOPIC);
        properties.getConsumer().setEnabled(true);
        properties.getConsumer().setPollTimeoutMs(Duration.ofMillis(50));
        properties.getConsumer().setRetryMaxAttempts(2);
        properties.getConsumer().setRetryBaseDelayMs(Duration.ofMillis(1));
        properties.getConsumer().setRetryMaxDelayMs(Duration.ofMillis(10));
        properties.getConsumer().setStorageFailurePolicy(KafkaFlowProperties.StorageFailurePolicy.PAUSE);

        when(normalizationService.ready()).thenReturn(true);
    }

    @AfterEach
    void tearDown() {
        if (consumer != null && consumer.isRunning()) {
            consumer.stop();
        }
    }

    @SuppressWarnings("unchecked")
    private KafkaFlowConsumer createConsumer() {
        Supplier<Consumer<String, String>> supplier = () -> kafkaConsumer;
        return new KafkaFlowConsumer(properties, codec, normalizationService, flowStore, dlqPublisher, supplier);
    }

    private ConsumerRecords<String, String> singleRecord(String value) {
        ConsumerRecord<String, String> record =
                new ConsumerRecord<>(RAW_TOPIC, 0, 0, "10.0.0.1", value);
        return new ConsumerRecords<>(Map.of(TP0, List.of(record)));
    }

    private ConsumerRecords<String, String> twoRecords(String value1, String value2) {
        ConsumerRecord<String, String> r1 = new ConsumerRecord<>(RAW_TOPIC, 0, 0, "10.0.0.1", value1);
        ConsumerRecord<String, String> r2 = new ConsumerRecord<>(RAW_TOPIC, 0, 1, "10.0.0.2", value2);
        return new ConsumerRecords<>(Map.of(TP0, List.of(r1, r2)));
    }

    private RawFlowRecord rawRecord() {
        return new RawFlowRecord("netflow-v5", "10.0.0.1", Instant.now(), Map.of("key", "val"));
    }

    // ── tests ───────────────────────────────────────────────────

    @Test
    @DisplayName("Valid records → inserted to store and committed")
    void processBatch_validRecords_insertsToStoreAndCommits() throws Exception {
        RawFlowRecord raw = rawRecord();
        NormalizedFlow flow = mock(NormalizedFlow.class);
        when(codec.decode(any())).thenReturn(raw);
        when(normalizationService.normalize(any())).thenReturn(flow);
        when(flowStore.batchInsert(anyList())).thenReturn(mock(WriteReceipt.class));

        AtomicInteger pollCount = new AtomicInteger();
        when(kafkaConsumer.poll(any(Duration.class))).thenAnswer(inv -> {
            if (pollCount.getAndIncrement() == 0) {
                return singleRecord("{\"valid\":true}");
            }
            return ConsumerRecords.empty();
        });

        consumer = createConsumer();
        consumer.start();

        verify(flowStore, timeout(2000)).batchInsert(anyList());
        verify(kafkaConsumer, timeout(2000)).commitSync();

        consumer.stop();
    }

    @Test
    @DisplayName("Invalid record (codec error) → published to DLQ")
    void processBatch_invalidRecord_publishesToDLQ() throws Exception {
        when(codec.decode(any())).thenThrow(new RawFlowRecordCodecException("bad json", new Exception()));
        when(dlqPublisher.publish(any())).thenReturn(CompletableFuture.completedFuture(null));

        AtomicInteger pollCount = new AtomicInteger();
        when(kafkaConsumer.poll(any(Duration.class))).thenAnswer(inv -> {
            if (pollCount.getAndIncrement() == 0) {
                return singleRecord("{invalid}");
            }
            return ConsumerRecords.empty();
        });

        consumer = createConsumer();
        consumer.start();

        verify(dlqPublisher, timeout(2000)).publish(any(DeadLetterFlowRecord.class));
        verify(flowStore, never()).batchInsert(anyList());

        consumer.stop();
    }

    @Test
    @DisplayName("Unsupported source type → published to DLQ")
    void processBatch_unsupportedSourceType_publishesToDLQ() throws Exception {
        RawFlowRecord raw = rawRecord();
        when(codec.decode(any())).thenReturn(raw);
        when(normalizationService.normalize(any()))
                .thenThrow(new UnsupportedSourceTypeException("unknown-type"));
        when(dlqPublisher.publish(any())).thenReturn(CompletableFuture.completedFuture(null));

        AtomicInteger pollCount = new AtomicInteger();
        when(kafkaConsumer.poll(any(Duration.class))).thenAnswer(inv -> {
            if (pollCount.getAndIncrement() == 0) {
                return singleRecord("{\"data\":1}");
            }
            return ConsumerRecords.empty();
        });

        consumer = createConsumer();
        consumer.start();

        verify(dlqPublisher, timeout(2000)).publish(any(DeadLetterFlowRecord.class));

        consumer.stop();
    }

    @Test
    @DisplayName("Validation error → published to DLQ with reason")
    void processBatch_validationError_publishesToDLQ() throws Exception {
        RawFlowRecord raw = rawRecord();
        when(codec.decode(any())).thenReturn(raw);
        when(normalizationService.normalize(any()))
                .thenThrow(new FlowValidationException("netflow-v5", "invalid_ip", "bad IP"));
        when(dlqPublisher.publish(any())).thenReturn(CompletableFuture.completedFuture(null));

        AtomicInteger pollCount = new AtomicInteger();
        when(kafkaConsumer.poll(any(Duration.class))).thenAnswer(inv -> {
            if (pollCount.getAndIncrement() == 0) {
                return singleRecord("{\"data\":1}");
            }
            return ConsumerRecords.empty();
        });

        consumer = createConsumer();
        consumer.start();

        verify(dlqPublisher, timeout(2000)).publish(any(DeadLetterFlowRecord.class));

        consumer.stop();
    }

    @Test
    @DisplayName("Mixed batch → valid records inserted, invalid to DLQ")
    void processBatch_mixedBatch_validStoredInvalidDLQ() throws Exception {
        RawFlowRecord raw = rawRecord();
        NormalizedFlow flow = mock(NormalizedFlow.class);

        AtomicInteger decodeCount = new AtomicInteger();
        when(codec.decode(any())).thenAnswer(inv -> {
            if (decodeCount.getAndIncrement() == 0) {
                return raw; // first record OK
            }
            throw new RawFlowRecordCodecException("bad", new Exception()); // second fails
        });
        when(normalizationService.normalize(any())).thenReturn(flow);
        when(flowStore.batchInsert(anyList())).thenReturn(mock(WriteReceipt.class));
        when(dlqPublisher.publish(any())).thenReturn(CompletableFuture.completedFuture(null));

        AtomicInteger pollCount = new AtomicInteger();
        when(kafkaConsumer.poll(any(Duration.class))).thenAnswer(inv -> {
            if (pollCount.getAndIncrement() == 0) {
                return twoRecords("{\"ok\":true}", "{bad}");
            }
            return ConsumerRecords.empty();
        });

        consumer = createConsumer();
        consumer.start();

        verify(flowStore, timeout(2000)).batchInsert(anyList());
        verify(dlqPublisher, timeout(2000)).publish(any(DeadLetterFlowRecord.class));

        consumer.stop();
    }

    @Test
    @DisplayName("Store failure with DLQ policy → sends to DLQ")
    void processBatch_storeFailsWithDLQPolicy_sendsAllToDLQ() throws Exception {
        properties.getConsumer().setStorageFailurePolicy(KafkaFlowProperties.StorageFailurePolicy.DLQ);

        RawFlowRecord raw = rawRecord();
        NormalizedFlow flow = mock(NormalizedFlow.class);
        when(codec.decode(any())).thenReturn(raw);
        when(normalizationService.normalize(any())).thenReturn(flow);
        when(flowStore.batchInsert(anyList())).thenThrow(new RuntimeException("ClickHouse down"));
        when(dlqPublisher.publish(any())).thenReturn(CompletableFuture.completedFuture(null));

        AtomicInteger pollCount = new AtomicInteger();
        when(kafkaConsumer.poll(any(Duration.class))).thenAnswer(inv -> {
            if (pollCount.getAndIncrement() == 0) {
                return singleRecord("{\"data\":1}");
            }
            return ConsumerRecords.empty();
        });

        consumer = createConsumer();
        consumer.start();

        verify(dlqPublisher, timeout(2000)).publish(any(DeadLetterFlowRecord.class));

        consumer.stop();
    }

    @Test
    @DisplayName("Store failure with PAUSE policy → pauses consumer, no commit")
    void processBatch_storeFailsWithPausePolicy_pausesConsumer() throws Exception {
        properties.getConsumer().setStorageFailurePolicy(KafkaFlowProperties.StorageFailurePolicy.PAUSE);

        RawFlowRecord raw = rawRecord();
        NormalizedFlow flow = mock(NormalizedFlow.class);
        when(codec.decode(any())).thenReturn(raw);
        when(normalizationService.normalize(any())).thenReturn(flow);
        when(flowStore.batchInsert(anyList())).thenThrow(new RuntimeException("ClickHouse down"));
        when(kafkaConsumer.assignment()).thenReturn(Set.of(TP0));

        AtomicInteger pollCount = new AtomicInteger();
        when(kafkaConsumer.poll(any(Duration.class))).thenAnswer(inv -> {
            if (pollCount.getAndIncrement() == 0) {
                return singleRecord("{\"data\":1}");
            }
            return ConsumerRecords.empty();
        });

        consumer = createConsumer();
        consumer.start();

        // Consumer should be paused
        Thread.sleep(500);
        assertThat(consumer.isPaused()).isTrue();

        consumer.stop();
    }

    @Test
    @DisplayName("DLQ publish fails → pauses consumer")
    void processBatch_dlqPublishFails_pausesConsumer() throws Exception {
        when(codec.decode(any())).thenThrow(new RawFlowRecordCodecException("bad", new Exception()));
        when(dlqPublisher.publish(any())).thenReturn(
                CompletableFuture.failedFuture(new RuntimeException("DLQ down")));
        when(kafkaConsumer.assignment()).thenReturn(Set.of(TP0));

        AtomicInteger pollCount = new AtomicInteger();
        when(kafkaConsumer.poll(any(Duration.class))).thenAnswer(inv -> {
            if (pollCount.getAndIncrement() == 0) {
                return singleRecord("{bad}");
            }
            return ConsumerRecords.empty();
        });

        consumer = createConsumer();
        consumer.start();

        Thread.sleep(500);
        assertThat(consumer.isPaused()).isTrue();

        consumer.stop();
    }

    @Test
    @DisplayName("Normalization not ready on record processing → pauses consumer")
    void processBatch_normalizationNotReady_pausesConsumer() throws Exception {
        RawFlowRecord raw = rawRecord();
        when(codec.decode(any())).thenReturn(raw);
        NormalizerCoverage coverage = NormalizerCoverage.of(
                Set.of("netflow-v5", "netflow-v9"), Set.of("netflow-v5"));
        when(normalizationService.normalize(any()))
                .thenThrow(new NormalizationServiceNotReadyException(coverage));
        when(kafkaConsumer.assignment()).thenReturn(Set.of(TP0));

        AtomicInteger pollCount = new AtomicInteger();
        when(kafkaConsumer.poll(any(Duration.class))).thenAnswer(inv -> {
            if (pollCount.getAndIncrement() == 0) {
                return singleRecord("{\"data\":1}");
            }
            return ConsumerRecords.empty();
        });

        consumer = createConsumer();
        consumer.start();

        Thread.sleep(500);
        assertThat(consumer.isPaused()).isTrue();

        consumer.stop();
    }

    @Test
    @DisplayName("Normalization not ready at start → does not start, isPaused=true")
    void start_normalizationNotReady_doesNotStart() {
        when(normalizationService.ready()).thenReturn(false);

        consumer = createConsumer();
        consumer.start();

        assertThat(consumer.isRunning()).isFalse();
        assertThat(consumer.isPaused()).isTrue();
    }

    @Test
    @DisplayName("Consumer disabled → does not start")
    void start_consumerDisabled_doesNotStart() {
        properties.getConsumer().setEnabled(false);

        consumer = createConsumer();
        consumer.start();

        assertThat(consumer.isRunning()).isFalse();
    }

    @Test
    @DisplayName("Stop → sets running to false")
    void stop_setsRunningFalse() {
        when(kafkaConsumer.poll(any(Duration.class))).thenReturn(ConsumerRecords.empty());

        consumer = createConsumer();
        consumer.start();

        assertThat(consumer.isRunning()).isTrue();

        consumer.stop();
        assertThat(consumer.isRunning()).isFalse();
    }

    @Test
    @DisplayName("insertWithRetry → succeeds after one retry")
    void insertWithRetry_succeedsAfterRetry() throws Exception {
        RawFlowRecord raw = rawRecord();
        NormalizedFlow flow = mock(NormalizedFlow.class);
        when(codec.decode(any())).thenReturn(raw);
        when(normalizationService.normalize(any())).thenReturn(flow);

        AtomicInteger insertCount = new AtomicInteger();
        when(flowStore.batchInsert(anyList())).thenAnswer(inv -> {
            if (insertCount.getAndIncrement() == 0) {
                throw new RuntimeException("transient failure");
            }
            return mock(WriteReceipt.class);
        });

        AtomicInteger pollCount = new AtomicInteger();
        when(kafkaConsumer.poll(any(Duration.class))).thenAnswer(inv -> {
            if (pollCount.getAndIncrement() == 0) {
                return singleRecord("{\"data\":1}");
            }
            return ConsumerRecords.empty();
        });

        consumer = createConsumer();
        consumer.start();

        verify(kafkaConsumer, timeout(2000)).commitSync();

        consumer.stop();
    }

    @Test
    @DisplayName("Dead letter truncates long payload")
    void deadLetter_truncatesLongPayload() throws Exception {
        // Build a payload > 16384 chars
        String longPayload = "x".repeat(20_000);
        when(codec.decode(any())).thenThrow(new RawFlowRecordCodecException("bad", new Exception()));
        when(dlqPublisher.publish(any())).thenAnswer(inv -> {
            DeadLetterFlowRecord dlq = inv.getArgument(0);
            // The rawPayload should be truncated to MAX_DLQ_PAYLOAD_CHARS=16384
            assertThat(dlq.rawPayload()).hasSize(16_384);
            return CompletableFuture.completedFuture(null);
        });

        AtomicInteger pollCount = new AtomicInteger();
        when(kafkaConsumer.poll(any(Duration.class))).thenAnswer(inv -> {
            if (pollCount.getAndIncrement() == 0) {
                ConsumerRecord<String, String> record =
                        new ConsumerRecord<>(RAW_TOPIC, 0, 0, "10.0.0.1", longPayload);
                return new ConsumerRecords<>(Map.of(TP0, List.of(record)));
            }
            return ConsumerRecords.empty();
        });

        consumer = createConsumer();
        consumer.start();

        verify(dlqPublisher, timeout(2000)).publish(any(DeadLetterFlowRecord.class));

        consumer.stop();
    }
}
