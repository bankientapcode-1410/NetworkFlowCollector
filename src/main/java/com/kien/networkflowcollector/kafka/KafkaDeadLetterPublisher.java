package com.kien.networkflowcollector.kafka;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Semaphore;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerRecord;

public class KafkaDeadLetterPublisher implements AutoCloseable {

    private static final String UNKNOWN_KEY = "unknown";

    private final Producer<String, String> producer;
    private final RawFlowRecordJsonCodec codec;
    private final String topic;
    private final Semaphore inFlightPermits;

    public KafkaDeadLetterPublisher(KafkaFlowProperties properties, RawFlowRecordJsonCodec codec) {
        this(
                new KafkaProducer<>(properties.producerProperties("dlq-producer")),
                codec,
                properties.getDlqTopic(),
                properties.getProducer().getMaxInFlightPublishes());
    }

    KafkaDeadLetterPublisher(
            Producer<String, String> producer,
            RawFlowRecordJsonCodec codec,
            String topic,
            int maxInFlightPublishes) {
        this.producer = Objects.requireNonNull(producer, "producer");
        this.codec = Objects.requireNonNull(codec, "codec");
        this.topic = Objects.requireNonNull(topic, "topic");
        this.inFlightPermits = new Semaphore(Math.max(1, maxInFlightPublishes));
    }

    public CompletionStage<Void> publish(DeadLetterFlowRecord record) {
        Objects.requireNonNull(record, "record");
        if (!inFlightPermits.tryAcquire()) {
            return CompletableFuture.failedFuture(
                    new PublishBackpressureException("Kafka DLQ publisher has no in-flight permits available"));
        }

        CompletableFuture<Void> future = new CompletableFuture<>();
        try {
            String key = record.exporterIp() == null || record.exporterIp().isBlank()
                    ? UNKNOWN_KEY
                    : record.exporterIp();
            ProducerRecord<String, String> producerRecord =
                    new ProducerRecord<>(topic, key, codec.encodeDeadLetter(record));
            producer.send(
                    producerRecord,
                    (metadata, exception) -> {
                        inFlightPermits.release();
                        if (exception == null) {
                            future.complete(null);
                        } else {
                            future.completeExceptionally(exception);
                        }
                    });
        } catch (RuntimeException e) {
            inFlightPermits.release();
            future.completeExceptionally(e);
        }
        return future;
    }

    @Override
    public void close() {
        producer.close(Duration.ofSeconds(10));
    }
}
