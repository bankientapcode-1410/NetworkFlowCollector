package com.kien.networkflowcollector.kafka;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kien.networkflowcollector.metrics.PipelineMetrics;
import com.kien.networkflowcollector.normalization.FlowNormalizationService;
import com.kien.networkflowcollector.storage.FlowStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

@DisplayName("KafkaFlowConfiguration")
class KafkaFlowConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(KafkaFlowConfiguration.class)
            .withBean(ObjectMapper.class, ObjectMapper::new)
            .withBean(PipelineMetrics.class, PipelineMetrics::unregistered)
            .withPropertyValues(
                    "nfc.kafka.bootstrap-servers=localhost:65535",
                    "nfc.kafka.raw-topic=raw-flows",
                    "nfc.kafka.dlq-topic=dead-letter-flows");

    @Test
    @DisplayName("Kafka enabled with storage creates the consumer bean")
    void kafkaEnabledWithStorageCreatesConsumerBean() {
        contextRunner
                .withBean(FlowNormalizationService.class, () -> mock(FlowNormalizationService.class))
                .withBean(FlowStore.class, () -> mock(FlowStore.class))
                .withPropertyValues("nfc.kafka.enabled=true")
                .run(context -> assertThat(context).hasSingleBean(KafkaFlowConsumer.class));
    }

    @Test
    @DisplayName("Consumer disabled skips the consumer bean without requiring storage")
    void consumerDisabledSkipsConsumerBeanWithoutRequiringStorage() {
        contextRunner
                .withPropertyValues(
                        "nfc.kafka.enabled=true",
                        "nfc.kafka.consumer.enabled=false")
                .run(context -> {
                    assertThat(context).hasSingleBean(KafkaFlowPublisher.class);
                    assertThat(context).hasSingleBean(KafkaDeadLetterPublisher.class);
                    assertThat(context).doesNotHaveBean(KafkaFlowConsumer.class);
                });
    }
}
