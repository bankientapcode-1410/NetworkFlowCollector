package com.kien.networkflowcollector.kafka;

import com.kien.networkflowcollector.metrics.PipelineMetrics;
import com.kien.networkflowcollector.spi.FlowPublisher;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Semaphore;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerRecord;

public class KafkaFlowPublisher implements FlowPublisher, AutoCloseable {

    private final Producer<String, String> producer;
    private final RawFlowRecordJsonCodec codec;
    private final String topic;
    private final Semaphore inFlightPermits;
    private final PipelineMetrics metrics;

    public KafkaFlowPublisher(KafkaFlowProperties properties, RawFlowRecordJsonCodec codec) {
        this(properties, codec, PipelineMetrics.unregistered());
    }

    public KafkaFlowPublisher(
            KafkaFlowProperties properties, RawFlowRecordJsonCodec codec, PipelineMetrics metrics) {
        this(
                new KafkaProducer<>(properties.producerProperties("raw-producer")),
                codec,
                properties.getRawTopic(),
                properties.getProducer().getMaxInFlightPublishes(),
                metrics);
    }

    KafkaFlowPublisher(
            Producer<String, String> producer,
            RawFlowRecordJsonCodec codec,
            String topic,
            int maxInFlightPublishes) {
        this(producer, codec, topic, maxInFlightPublishes, PipelineMetrics.unregistered());
    }

    KafkaFlowPublisher(
            Producer<String, String> producer,
            RawFlowRecordJsonCodec codec,
            String topic,
            int maxInFlightPublishes,
            PipelineMetrics metrics) {
        this.producer = Objects.requireNonNull(producer, "producer");
        this.codec = Objects.requireNonNull(codec, "codec");
        this.topic = Objects.requireNonNull(topic, "topic");
        this.inFlightPermits = new Semaphore(Math.max(1, maxInFlightPublishes));
        this.metrics = Objects.requireNonNull(metrics, "metrics");
    }

    @Override
    public CompletionStage<Void> publish(RawFlowRecord record) {
        Objects.requireNonNull(record, "record");
        if (!inFlightPermits.tryAcquire()) {
            return CompletableFuture.failedFuture(
                    new PublishBackpressureException("Kafka publisher has no in-flight permits available"));
        }

        CompletableFuture<Void> future = new CompletableFuture<>();
        try {
            String value = codec.encode(record);
            ProducerRecord<String, String> producerRecord =
                    new ProducerRecord<>(topic, record.exporterIp(), value);
            producer.send(
                    producerRecord,
                    (metadata, exception) -> {
                        inFlightPermits.release();
                        if (exception == null) {
                            metrics.recordCollected(record.sourceType());
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
