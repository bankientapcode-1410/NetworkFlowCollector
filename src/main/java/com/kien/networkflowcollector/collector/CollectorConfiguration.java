package com.kien.networkflowcollector.collector;

import com.kien.networkflowcollector.spi.FlowPublisher;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(CollectorProperties.class)
public class CollectorConfiguration {

    @Bean
    CollectorRegistry collectorRegistry(
            CollectorProperties properties, ObjectProvider<FlowPublisher> publisherProvider) {
        return new CollectorRegistry(properties, publisherProvider);
    }
}
