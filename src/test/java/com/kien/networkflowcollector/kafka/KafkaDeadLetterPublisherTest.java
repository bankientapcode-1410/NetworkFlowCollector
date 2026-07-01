package com.kien.networkflowcollector.kafka;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
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

@DisplayName("KafkaDeadLetterPublisher")
class KafkaDeadLetterPublisherTest {

    @SuppressWarnings("unchecked")
    private final Producer<String, String> producer = mock(Producer.class);
    private final RawFlowRecordJsonCodec codec = mock(RawFlowRecordJsonCodec.class);
    private static final String DLQ_TOPIC = "dead-letter-flows";

    private KafkaDeadLetterPublisher publisher;

    @BeforeEach
    void setUp() {
        publisher = new KafkaDeadLetterPublisher(producer, codec, DLQ_TOPIC, 10);
    }

    private DeadLetterFlowRecord sampleRecord(String exporterIp) {
        return new DeadLetterFlowRecord(
                "netflow-v5", exporterIp, Instant.now(), Instant.now(),
                "invalid_record", "parse error", null, "{bad json}");
    }

    @Test
    @DisplayName("Valid record → sends to dead-letter-flows topic")
    @SuppressWarnings("unchecked")
    void publish_validRecord_sendsToDeadLetterTopic() {
        when(codec.encodeDeadLetter(any())).thenReturn("{\"dlq\":true}");
        doAnswer(inv -> {
            Callback cb = inv.getArgument(1);
            cb.onCompletion(new RecordMetadata(new TopicPartition(DLQ_TOPIC, 0), 0, 0, 0, 0, 0), null);
            return null;
        }).when(producer).send(any(ProducerRecord.class), any(Callback.class));

        publisher.publish(sampleRecord("10.0.0.1"));

        ArgumentCaptor<ProducerRecord<String, String>> captor = ArgumentCaptor.forClass(ProducerRecord.class);
        verify(producer).send(captor.capture(), any(Callback.class));
        assertThat(captor.getValue().topic()).isEqualTo(DLQ_TOPIC);
    }

    @Test
    @DisplayName("Non-blank exporterIp → used as key")
    @SuppressWarnings("unchecked")
    void publish_keyIsExporterIp() {
        when(codec.encodeDeadLetter(any())).thenReturn("{}");
        doAnswer(inv -> {
            Callback cb = inv.getArgument(1);
            cb.onCompletion(new RecordMetadata(new TopicPartition(DLQ_TOPIC, 0), 0, 0, 0, 0, 0), null);
            return null;
        }).when(producer).send(any(ProducerRecord.class), any(Callback.class));

        publisher.publish(sampleRecord("10.0.0.1"));

        ArgumentCaptor<ProducerRecord<String, String>> captor = ArgumentCaptor.forClass(ProducerRecord.class);
        verify(producer).send(captor.capture(), any(Callback.class));
        assertThat(captor.getValue().key()).isEqualTo("10.0.0.1");
    }

    @Test
    @DisplayName("Null exporterIp → key = 'unknown'")
    @SuppressWarnings("unchecked")
    void publish_nullExporterIp_usesUnknownKey() {
        when(codec.encodeDeadLetter(any())).thenReturn("{}");
        doAnswer(inv -> {
            Callback cb = inv.getArgument(1);
            cb.onCompletion(new RecordMetadata(new TopicPartition(DLQ_TOPIC, 0), 0, 0, 0, 0, 0), null);
            return null;
        }).when(producer).send(any(ProducerRecord.class), any(Callback.class));

        publisher.publish(sampleRecord(null));

        ArgumentCaptor<ProducerRecord<String, String>> captor = ArgumentCaptor.forClass(ProducerRecord.class);
        verify(producer).send(captor.capture(), any(Callback.class));
        assertThat(captor.getValue().key()).isEqualTo("unknown");
    }

    @Test
    @DisplayName("Blank exporterIp → key = 'unknown'")
    @SuppressWarnings("unchecked")
    void publish_blankExporterIp_usesUnknownKey() {
        when(codec.encodeDeadLetter(any())).thenReturn("{}");
        doAnswer(inv -> {
            Callback cb = inv.getArgument(1);
            cb.onCompletion(new RecordMetadata(new TopicPartition(DLQ_TOPIC, 0), 0, 0, 0, 0, 0), null);
            return null;
        }).when(producer).send(any(ProducerRecord.class), any(Callback.class));

        publisher.publish(sampleRecord("  "));

        ArgumentCaptor<ProducerRecord<String, String>> captor = ArgumentCaptor.forClass(ProducerRecord.class);
        verify(producer).send(captor.capture(), any(Callback.class));
        assertThat(captor.getValue().key()).isEqualTo("unknown");
    }

    @Test
    @DisplayName("Kafka ack → future completes successfully")
    @SuppressWarnings("unchecked")
    void publish_kafkaAck_completesSuccessfully() throws Exception {
        when(codec.encodeDeadLetter(any())).thenReturn("{}");
        doAnswer(inv -> {
            Callback cb = inv.getArgument(1);
            cb.onCompletion(new RecordMetadata(new TopicPartition(DLQ_TOPIC, 0), 0, 0, 0, 0, 0), null);
            return null;
        }).when(producer).send(any(ProducerRecord.class), any(Callback.class));

        CompletionStage<Void> result = publisher.publish(sampleRecord("10.0.0.1"));

        assertThat(result.toCompletableFuture().isDone()).isTrue();
        assertThat(result.toCompletableFuture().isCompletedExceptionally()).isFalse();
    }

    @Test
    @DisplayName("Backpressure → failed future with PublishBackpressureException")
    void publish_backpressure_returnsFailedFuture() {
        KafkaDeadLetterPublisher limited = new KafkaDeadLetterPublisher(producer, codec, DLQ_TOPIC, 1);
        when(codec.encodeDeadLetter(any())).thenReturn("{}");
        doAnswer(inv -> null).when(producer).send(any(), any()); // Don't invoke callback

        limited.publish(sampleRecord("10.0.0.1")); // Takes the 1 permit

        CompletionStage<Void> result = limited.publish(sampleRecord("10.0.0.1"));
        assertThat(result.toCompletableFuture().isCompletedExceptionally()).isTrue();
        assertThatThrownBy(() -> result.toCompletableFuture().get())
                .isInstanceOf(ExecutionException.class)
                .hasCauseInstanceOf(PublishBackpressureException.class);
    }

    @Test
    @DisplayName("Null record → NullPointerException")
    void publish_nullRecord_throwsNPE() {
        assertThatThrownBy(() -> publisher.publish(null))
                .isInstanceOf(NullPointerException.class);
    }
}
