package com.kien.networkflowcollector.kafka;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import org.apache.kafka.clients.producer.Callback;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.kafka.common.TopicPartition;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

@DisplayName("KafkaFlowPublisher")
class KafkaFlowPublisherTest {

    @SuppressWarnings("unchecked")
    private final Producer<String, String> producer = mock(Producer.class);
    private final RawFlowRecordJsonCodec codec = mock(RawFlowRecordJsonCodec.class);
    private static final String TOPIC = "raw-flows";
    private static final Instant NOW = Instant.now();

    private KafkaFlowPublisher publisher;

    @BeforeEach
    void setUp() {
        publisher = new KafkaFlowPublisher(producer, codec, TOPIC, 10);
    }

    private RawFlowRecord sampleRecord() {
        return new RawFlowRecord("netflow-v5", "10.0.0.1", NOW, Map.of("key", "val"));
    }

    @Test
    @DisplayName("Valid record → sends to correct topic with exporterIp as key")
    @SuppressWarnings("unchecked")
    void publish_validRecord_sendsToRawFlowsTopic() {
        when(codec.encode(any())).thenReturn("{\"json\":true}");
        doAnswer(inv -> {
            Callback cb = inv.getArgument(1);
            cb.onCompletion(new RecordMetadata(new TopicPartition(TOPIC, 0), 0, 0, 0, 0, 0), null);
            return null;
        }).when(producer).send(any(ProducerRecord.class), any(Callback.class));

        publisher.publish(sampleRecord());

        ArgumentCaptor<ProducerRecord<String, String>> captor = ArgumentCaptor.forClass(ProducerRecord.class);
        verify(producer).send(captor.capture(), any(Callback.class));
        assertThat(captor.getValue().topic()).isEqualTo(TOPIC);
        assertThat(captor.getValue().key()).isEqualTo("10.0.0.1");
    }

    @Test
    @DisplayName("Kafka ack → future completes successfully")
    @SuppressWarnings("unchecked")
    void publish_kafkaAck_completesSuccessfully() throws Exception {
        when(codec.encode(any())).thenReturn("{}");
        doAnswer(inv -> {
            Callback cb = inv.getArgument(1);
            cb.onCompletion(new RecordMetadata(new TopicPartition(TOPIC, 0), 0, 0, 0, 0, 0), null);
            return null;
        }).when(producer).send(any(ProducerRecord.class), any(Callback.class));

        CompletionStage<Void> result = publisher.publish(sampleRecord());

        assertThat(result.toCompletableFuture().isDone()).isTrue();
        assertThat(result.toCompletableFuture().isCompletedExceptionally()).isFalse();
    }

    @Test
    @DisplayName("Kafka error → future completes exceptionally")
    @SuppressWarnings("unchecked")
    void publish_kafkaError_completesExceptionally() {
        when(codec.encode(any())).thenReturn("{}");
        RuntimeException kafkaError = new RuntimeException("Kafka send failed");
        doAnswer(inv -> {
            Callback cb = inv.getArgument(1);
            cb.onCompletion(null, kafkaError);
            return null;
        }).when(producer).send(any(ProducerRecord.class), any(Callback.class));

        CompletionStage<Void> result = publisher.publish(sampleRecord());

        assertThat(result.toCompletableFuture().isCompletedExceptionally()).isTrue();
    }

    @Test
    @DisplayName("Backpressure → returns failed future with PublishBackpressureException")
    void publish_backpressure_returnsFailedFuture() {
        // Publisher with only 1 permit, and we exhaust it
        KafkaFlowPublisher limited = new KafkaFlowPublisher(producer, codec, TOPIC, 1);
        when(codec.encode(any())).thenReturn("{}");
        // First publish — don't invoke callback so permit stays consumed
        doAnswer(inv -> null).when(producer).send(any(), any());

        limited.publish(sampleRecord()); // Takes the 1 permit

        CompletionStage<Void> result = limited.publish(sampleRecord());
        assertThat(result.toCompletableFuture().isCompletedExceptionally()).isTrue();
        assertThatThrownBy(() -> result.toCompletableFuture().get())
                .isInstanceOf(ExecutionException.class)
                .hasCauseInstanceOf(PublishBackpressureException.class);
    }

    @Test
    @DisplayName("Permit released after successful callback")
    @SuppressWarnings("unchecked")
    void publish_permitReleasedOnSuccess() throws Exception {
        KafkaFlowPublisher limited = new KafkaFlowPublisher(producer, codec, TOPIC, 1);
        when(codec.encode(any())).thenReturn("{}");
        doAnswer(inv -> {
            Callback cb = inv.getArgument(1);
            cb.onCompletion(new RecordMetadata(new TopicPartition(TOPIC, 0), 0, 0, 0, 0, 0), null);
            return null;
        }).when(producer).send(any(ProducerRecord.class), any(Callback.class));

        // First publish succeeds → permit released
        limited.publish(sampleRecord()).toCompletableFuture().get();
        // Second publish should also succeed (permit available again)
        CompletionStage<Void> second = limited.publish(sampleRecord());
        assertThat(second.toCompletableFuture().isDone()).isTrue();
    }

    @Test
    @DisplayName("Permit released after error callback")
    @SuppressWarnings("unchecked")
    void publish_permitReleasedOnError() {
        KafkaFlowPublisher limited = new KafkaFlowPublisher(producer, codec, TOPIC, 1);
        when(codec.encode(any())).thenReturn("{}");
        doAnswer(inv -> {
            Callback cb = inv.getArgument(1);
            cb.onCompletion(null, new RuntimeException("fail"));
            return null;
        }).when(producer).send(any(ProducerRecord.class), any(Callback.class));

        limited.publish(sampleRecord()); // Error but permit released

        // Second publish should also work (permit available)
        doAnswer(inv -> {
            Callback cb = inv.getArgument(1);
            cb.onCompletion(new RecordMetadata(new TopicPartition(TOPIC, 0), 0, 0, 0, 0, 0), null);
            return null;
        }).when(producer).send(any(ProducerRecord.class), any(Callback.class));

        CompletionStage<Void> second = limited.publish(sampleRecord());
        assertThat(second.toCompletableFuture().isDone()).isTrue();
        assertThat(second.toCompletableFuture().isCompletedExceptionally()).isFalse();
    }

    @Test
    @DisplayName("codec.encode() is invoked")
    void publish_codecEncodesCalled() {
        when(codec.encode(any())).thenReturn("{}");
        doAnswer(inv -> {
            Callback cb = inv.getArgument(1);
            cb.onCompletion(new RecordMetadata(new TopicPartition(TOPIC, 0), 0, 0, 0, 0, 0), null);
            return null;
        }).when(producer).send(any(), any());

        RawFlowRecord record = sampleRecord();
        publisher.publish(record);

        verify(codec).encode(record);
    }

    @Test
    @DisplayName("Null record → NullPointerException")
    void publish_nullRecord_throwsNPE() {
        assertThatThrownBy(() -> publisher.publish(null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("Encoding error → future completes exceptionally, permit released")
    void publish_encodingError_completesExceptionally() {
        when(codec.encode(any())).thenThrow(new RawFlowRecordCodecException("encode fail", new Exception()));

        CompletionStage<Void> result = publisher.publish(sampleRecord());

        assertThat(result.toCompletableFuture().isCompletedExceptionally()).isTrue();
    }

    @Test
    @DisplayName("close() delegates to producer.close()")
    void close_closesProducer() {
        publisher.close();

        verify(producer).close(any());
    }
}
