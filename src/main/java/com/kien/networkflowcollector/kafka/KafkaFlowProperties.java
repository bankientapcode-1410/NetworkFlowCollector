package com.kien.networkflowcollector.kafka;

import java.time.Duration;
import java.util.Properties;
import lombok.Getter;
import lombok.Setter;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "nfc.kafka")
public class KafkaFlowProperties {

    private boolean enabled;
    private String bootstrapServers = "localhost:9092";
    private String rawTopic = "raw-flows";
    private String dlqTopic = "dead-letter-flows";
    private String clientId = "network-flow-collector";
    private final Producer producer = new Producer();
    private final Consumer consumer = new Consumer();

    Properties producerProperties(String clientIdSuffix) {
        Properties properties = new Properties();
        properties.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        properties.put(ProducerConfig.CLIENT_ID_CONFIG, clientId + "-" + clientIdSuffix);
        properties.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        properties.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        properties.put(ProducerConfig.ACKS_CONFIG, producer.acks);
        properties.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, producer.idempotence);
        properties.put(ProducerConfig.RETRIES_CONFIG, producer.retries);
        properties.put(ProducerConfig.RETRY_BACKOFF_MS_CONFIG, producer.retryBackoffMs.toMillis());
        properties.put(
                ProducerConfig.DELIVERY_TIMEOUT_MS_CONFIG,
                durationMillisAsInt(producer.deliveryTimeoutMs, ProducerConfig.DELIVERY_TIMEOUT_MS_CONFIG));
        properties.put(
                ProducerConfig.REQUEST_TIMEOUT_MS_CONFIG,
                durationMillisAsInt(producer.requestTimeoutMs, ProducerConfig.REQUEST_TIMEOUT_MS_CONFIG));
        properties.put(ProducerConfig.LINGER_MS_CONFIG, producer.lingerMs.toMillis());
        properties.put(ProducerConfig.BATCH_SIZE_CONFIG, producer.batchSizeBytes);
        properties.put(
                ProducerConfig.MAX_IN_FLIGHT_REQUESTS_PER_CONNECTION,
                producer.maxInFlightRequestsPerConnection);
        return properties;
    }

    private static int durationMillisAsInt(Duration duration, String propertyName) {
        long millis = duration.toMillis();
        if (millis > Integer.MAX_VALUE) {
            throw new IllegalArgumentException(propertyName + " must be <= " + Integer.MAX_VALUE + " ms");
        }
        return Math.toIntExact(millis);
    }

    Properties consumerProperties() {
        Properties properties = new Properties();
        properties.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        properties.put(ConsumerConfig.CLIENT_ID_CONFIG, consumer.clientId);
        properties.put(ConsumerConfig.GROUP_ID_CONFIG, consumer.groupId);
        properties.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        properties.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        properties.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, false);
        properties.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, consumer.autoOffsetReset);
        properties.put(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, consumer.batchMaxRecords);
        return properties;
    }

    @Getter
    @Setter
    public static class Producer {

        private String acks = "all";
        private boolean idempotence = true;
        private int retries = 8;
        private Duration retryBackoffMs = Duration.ofMillis(200);
        private Duration deliveryTimeoutMs = Duration.ofMinutes(2);
        private Duration requestTimeoutMs = Duration.ofSeconds(30);
        private Duration lingerMs = Duration.ofMillis(10);
        private int batchSizeBytes = 131_072;
        private int maxInFlightRequestsPerConnection = 5;
        private int maxInFlightPublishes = 50_000;
    }

    @Getter
    @Setter
    public static class Consumer {

        private boolean enabled = true;
        private String groupId = "flow-normalization-service";
        private String clientId = "flow-normalization-consumer";
        private String autoOffsetReset = "earliest";
        private int batchMaxRecords = 5_000;
        private Duration pollTimeoutMs = Duration.ofSeconds(1);
        private int retryMaxAttempts = 8;
        private Duration retryBaseDelayMs = Duration.ofMillis(200);
        private Duration retryMaxDelayMs = Duration.ofSeconds(30);
        private StorageFailurePolicy storageFailurePolicy = StorageFailurePolicy.PAUSE;
    }

    public enum StorageFailurePolicy {
        PAUSE,
        DLQ
    }
}
