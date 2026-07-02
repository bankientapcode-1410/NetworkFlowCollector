package com.kien.networkflowcollector.kafka;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.normalization.FlowNormalizationService;
import com.kien.networkflowcollector.normalization.FlowValidationException;
import com.kien.networkflowcollector.normalization.NormalizationServiceNotReadyException;
import com.kien.networkflowcollector.normalization.UnsupportedSourceTypeException;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import com.kien.networkflowcollector.storage.FlowStore;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import org.apache.kafka.clients.consumer.ConsumerRebalanceListener;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.errors.WakeupException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.SmartLifecycle;

public class KafkaFlowConsumer implements SmartLifecycle {

    private static final Logger LOGGER = LoggerFactory.getLogger(KafkaFlowConsumer.class);
    private static final int MAX_DLQ_PAYLOAD_CHARS = 16_384;

    private final KafkaFlowProperties properties;
    private final RawFlowRecordJsonCodec codec;
    private final FlowNormalizationService normalizationService;
    private final FlowStore flowStore;
    private final KafkaDeadLetterPublisher deadLetterPublisher;
    private final Supplier<org.apache.kafka.clients.consumer.Consumer<String, String>> consumerSupplier;
    private final AtomicBoolean running = new AtomicBoolean();

    private volatile Thread worker;
    private volatile org.apache.kafka.clients.consumer.Consumer<String, String> consumer;
    private volatile boolean paused;
    private volatile long pausedUntilNanos;
    private int pauseAttempts;

    public KafkaFlowConsumer(
            KafkaFlowProperties properties,
            RawFlowRecordJsonCodec codec,
            FlowNormalizationService normalizationService,
            FlowStore flowStore,
            KafkaDeadLetterPublisher deadLetterPublisher) {
        this(
                properties,
                codec,
                normalizationService,
                flowStore,
                deadLetterPublisher,
                () -> new KafkaConsumer<>(properties.consumerProperties()));
    }

    KafkaFlowConsumer(
            KafkaFlowProperties properties,
            RawFlowRecordJsonCodec codec,
            FlowNormalizationService normalizationService,
            FlowStore flowStore,
            KafkaDeadLetterPublisher deadLetterPublisher,
            Supplier<org.apache.kafka.clients.consumer.Consumer<String, String>> consumerSupplier) {
        this.properties = Objects.requireNonNull(properties, "properties");
        this.codec = Objects.requireNonNull(codec, "codec");
        this.normalizationService = Objects.requireNonNull(normalizationService, "normalizationService");
        this.flowStore = Objects.requireNonNull(flowStore, "flowStore");
        this.deadLetterPublisher = Objects.requireNonNull(deadLetterPublisher, "deadLetterPublisher");
        this.consumerSupplier = Objects.requireNonNull(consumerSupplier, "consumerSupplier");
    }

    @Override
    public void start() {
        if (!properties.getConsumer().isEnabled() || !running.compareAndSet(false, true)) {
            return;
        }
        if (!normalizationService.ready()) {
            running.set(false);
            paused = true;
            LOGGER.warn("Kafka consumer not started because normalizer coverage is incomplete");
            return;
        }
        paused = false;
        pausedUntilNanos = 0;
        pauseAttempts = 0;
        Thread newWorker = new Thread(this::pollLoop, "kafka-flow-consumer");
        newWorker.setDaemon(true);
        worker = newWorker;
        newWorker.start();
    }

    @Override
    public void stop() {
        if (!running.compareAndSet(true, false)) {
            return;
        }
        org.apache.kafka.clients.consumer.Consumer<String, String> currentConsumer = consumer;
        if (currentConsumer != null) {
            currentConsumer.wakeup();
        }
        Thread currentWorker = worker;
        if (currentWorker != null) {
            try {
                currentWorker.join(Duration.ofSeconds(10).toMillis());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    @Override
    public boolean isRunning() {
        return running.get();
    }

    @Override
    public int getPhase() {
        return Integer.MAX_VALUE - 100;
    }

    boolean isPaused() {
        return paused;
    }

    private void pollLoop() {
        try (org.apache.kafka.clients.consumer.Consumer<String, String> kafkaConsumer = consumerSupplier.get()) {
            consumer = kafkaConsumer;
            kafkaConsumer.subscribe(
                    List.of(properties.getRawTopic()),
                    new ConsumerRebalanceListener() {
                        @Override
                        public void onPartitionsRevoked(Collection<TopicPartition> partitions) {
                            // Processing code owns commits; rebalance callbacks only keep pause state.
                        }

                        @Override
                        public void onPartitionsAssigned(Collection<TopicPartition> partitions) {
                            if (paused && !partitions.isEmpty()) {
                                kafkaConsumer.pause(partitions);
                            }
                        }
                    });
            while (running.get()) {
                if (paused) {
                    pauseAssignedPartitions(kafkaConsumer);
                    ConsumerRecords<String, String> records = pollRecords(kafkaConsumer);
                    rewindPausedRecords(kafkaConsumer, records);
                    maybeResumeConsumption(kafkaConsumer);
                    continue;
                }
                ConsumerRecords<String, String> records = pollRecords(kafkaConsumer);
                if (records.isEmpty()) {
                    continue;
                }
                try {
                    if (processBatch(records)) {
                        kafkaConsumer.commitSync();
                        markProcessingHealthy();
                    }
                } catch (NormalizationServiceNotReadyException e) {
                    pauseConsumption(
                            "Normalizer coverage became incomplete; offsets remain uncommitted", e);
                } catch (RuntimeException e) {
                    pauseConsumption("Kafka batch processing failed; offsets remain uncommitted", e);
                }
            }
        } catch (WakeupException e) {
            if (running.get()) {
                throw e;
            }
        } catch (KafkaException e) {
            paused = true;
            LOGGER.error("Kafka consumer stopped after Kafka error", e);
        } finally {
            consumer = null;
            running.set(false);
        }
    }

    private boolean processBatch(ConsumerRecords<String, String> records) {
        ProcessedBatch processed = normalizeRecords(records);
        if (!processed.validFlows().isEmpty()) {
            try {
                insertWithRetry(processed.validFlows());
            } catch (RuntimeException e) {
                if (properties.getConsumer().getStorageFailurePolicy()
                        == KafkaFlowProperties.StorageFailurePolicy.DLQ) {
                    publishDeadLetters(
                            processed.validRawRecords().stream()
                                    .map(raw -> deadLetter(
                                            raw.record(),
                                            raw.rawPayload(),
                                            "storage_retry_exhausted",
                                            e))
                                    .toList());
                } else {
                    pauseConsumption("ClickHouse insert failed after retry; offsets remain uncommitted", e);
                    return false;
                }
            }
        }

        try {
            publishDeadLetters(processed.deadLetters());
            return true;
        } catch (RuntimeException e) {
            pauseConsumption("DLQ publish failed; offsets remain uncommitted", e);
            return false;
        }
    }

    private ProcessedBatch normalizeRecords(ConsumerRecords<String, String> records) {
        List<DecodedRawRecord> validRawRecords = new ArrayList<>();
        List<NormalizedFlow> validFlows = new ArrayList<>();
        List<DeadLetterFlowRecord> deadLetters = new ArrayList<>();

        for (ConsumerRecord<String, String> record : records) {
            RawFlowRecord raw = null;
            try {
                raw = codec.decode(record.value());
                validFlows.add(normalizationService.normalize(raw));
                validRawRecords.add(new DecodedRawRecord(raw, record.value()));
            } catch (NormalizationServiceNotReadyException e) {
                throw e;
            } catch (RawFlowRecordCodecException e) {
                deadLetters.add(deadLetter(null, record.value(), "invalid_raw_record", e));
            } catch (UnsupportedSourceTypeException e) {
                deadLetters.add(deadLetter(raw, record.value(), "unsupported_source_type", e));
            } catch (FlowValidationException e) {
                deadLetters.add(deadLetter(raw, record.value(), e.reason(), e));
            } catch (RuntimeException e) {
                deadLetters.add(deadLetter(raw, record.value(), "normalization_error", e));
            }
        }

        return new ProcessedBatch(validRawRecords, validFlows, deadLetters);
    }

    private void insertWithRetry(List<NormalizedFlow> flows) {
        int maxAttempts = Math.max(1, properties.getConsumer().getRetryMaxAttempts());
        RuntimeException last = null;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                flowStore.batchInsert(flows);
                return;
            } catch (RuntimeException e) {
                last = e;
                if (attempt < maxAttempts) {
                    sleep(backoff(attempt));
                }
            }
        }
        throw last == null ? new IllegalStateException("ClickHouse insert failed") : last;
    }

    private void publishDeadLetters(List<DeadLetterFlowRecord> deadLetters) {
        for (DeadLetterFlowRecord deadLetter : deadLetters) {
            try {
                deadLetterPublisher.publish(deadLetter).toCompletableFuture().get();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted while publishing DLQ record", e);
            } catch (ExecutionException e) {
                throw new IllegalStateException("Failed to publish DLQ record", e.getCause());
            }
        }
    }

    private DeadLetterFlowRecord deadLetter(
            RawFlowRecord raw, String rawPayload, String reason, RuntimeException error) {
        return new DeadLetterFlowRecord(
                raw == null ? "unsupported" : raw.sourceType(),
                raw == null ? null : raw.exporterIp(),
                raw == null ? null : raw.receivedAt(),
                Instant.now(),
                reason,
                error.getMessage(),
                raw,
                truncate(rawPayload));
    }

    private void pauseConsumption(String message, RuntimeException error) {
        paused = true;
        pauseAttempts++;
        pausedUntilNanos = System.nanoTime() + backoff(pauseAttempts).toNanos();
        org.apache.kafka.clients.consumer.Consumer<String, String> currentConsumer = consumer;
        if (currentConsumer != null) {
            pauseAssignedPartitions(currentConsumer);
        }
        LOGGER.error(message, error);
    }

    private ConsumerRecords<String, String> pollRecords(
            org.apache.kafka.clients.consumer.Consumer<String, String> kafkaConsumer) {
        try {
            return kafkaConsumer.poll(properties.getConsumer().getPollTimeoutMs());
        } catch (WakeupException e) {
            throw e;
        } catch (KafkaException e) {
            pauseConsumption("Kafka poll failed; consumer will retry after backoff", e);
            return ConsumerRecords.empty();
        }
    }

    private void pauseAssignedPartitions(
            org.apache.kafka.clients.consumer.Consumer<String, String> kafkaConsumer) {
        Set<TopicPartition> assignment = kafkaConsumer.assignment();
        if (!assignment.isEmpty()) {
            kafkaConsumer.pause(assignment);
        }
    }

    private void maybeResumeConsumption(
            org.apache.kafka.clients.consumer.Consumer<String, String> kafkaConsumer) {
        if (!normalizationService.ready() || System.nanoTime() - pausedUntilNanos < 0) {
            return;
        }
        Set<TopicPartition> assignment = kafkaConsumer.assignment();
        if (!assignment.isEmpty()) {
            kafkaConsumer.resume(assignment);
        }
        paused = false;
        LOGGER.info("Kafka consumer resumed after pause");
    }

    private void rewindPausedRecords(
            org.apache.kafka.clients.consumer.Consumer<String, String> kafkaConsumer,
            ConsumerRecords<String, String> records) {
        if (records.isEmpty()) {
            return;
        }
        for (TopicPartition partition : records.partitions()) {
            List<ConsumerRecord<String, String>> partitionRecords = records.records(partition);
            if (!partitionRecords.isEmpty()) {
                kafkaConsumer.seek(partition, partitionRecords.getFirst().offset());
            }
        }
    }

    private void markProcessingHealthy() {
        pauseAttempts = 0;
        pausedUntilNanos = 0;
    }

    private Duration backoff(int attempt) {
        long baseMs = Math.max(1, properties.getConsumer().getRetryBaseDelayMs().toMillis());
        long maxMs = Math.max(baseMs, properties.getConsumer().getRetryMaxDelayMs().toMillis());
        long multiplier = 1L << Math.min(20, Math.max(0, attempt - 1));
        long exponential = baseMs > Long.MAX_VALUE / multiplier ? Long.MAX_VALUE : baseMs * multiplier;
        long jitter = ThreadLocalRandom.current().nextLong(baseMs);
        long delayMs = exponential > Long.MAX_VALUE - jitter ? Long.MAX_VALUE : exponential + jitter;
        return Duration.ofMillis(Math.min(maxMs, delayMs));
    }

    private static void sleep(Duration duration) {
        try {
            Thread.sleep(duration.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static String truncate(String value) {
        if (value == null || value.length() <= MAX_DLQ_PAYLOAD_CHARS) {
            return value;
        }
        return value.substring(0, MAX_DLQ_PAYLOAD_CHARS);
    }

    private record ProcessedBatch(
            List<DecodedRawRecord> validRawRecords,
            List<NormalizedFlow> validFlows,
            List<DeadLetterFlowRecord> deadLetters) {}

    private record DecodedRawRecord(RawFlowRecord record, String rawPayload) {}
}
