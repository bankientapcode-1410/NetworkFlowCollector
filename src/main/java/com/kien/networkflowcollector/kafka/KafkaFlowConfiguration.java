package com.kien.networkflowcollector.kafka;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kien.networkflowcollector.metrics.PipelineMetrics;
import com.kien.networkflowcollector.normalization.FlowNormalizationService;
import com.kien.networkflowcollector.storage.FlowStore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(KafkaFlowProperties.class)
public class KafkaFlowConfiguration {

    @Bean
    RawFlowRecordJsonCodec rawFlowRecordJsonCodec(ObjectMapper objectMapper) {
        return new RawFlowRecordJsonCodec(objectMapper);
    }

    @Bean(destroyMethod = "close")
    @ConditionalOnProperty(prefix = "nfc.kafka", name = "enabled", havingValue = "true")
    KafkaFlowPublisher kafkaFlowPublisher(
            KafkaFlowProperties properties, RawFlowRecordJsonCodec codec, PipelineMetrics metrics) {
        return new KafkaFlowPublisher(properties, codec, metrics);
    }

    @Bean(destroyMethod = "close")
    @ConditionalOnProperty(prefix = "nfc.kafka", name = "enabled", havingValue = "true")
    KafkaDeadLetterPublisher kafkaDeadLetterPublisher(
            KafkaFlowProperties properties, RawFlowRecordJsonCodec codec) {
        return new KafkaDeadLetterPublisher(properties, codec);
    }

    @Bean
    @ConditionalOnBean({KafkaDeadLetterPublisher.class, FlowStore.class})
    @ConditionalOnProperty(prefix = "nfc.kafka", name = "enabled", havingValue = "true")
    KafkaFlowConsumer kafkaFlowConsumer(
            KafkaFlowProperties properties,
            RawFlowRecordJsonCodec codec,
            FlowNormalizationService normalizationService,
            FlowStore flowStore,
            KafkaDeadLetterPublisher deadLetterPublisher) {
        return new KafkaFlowConsumer(properties, codec, normalizationService, flowStore, deadLetterPublisher);
    }
}
