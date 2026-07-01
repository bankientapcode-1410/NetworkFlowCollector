package com.kien.networkflowcollector.storage.clickhouse;

import com.kien.networkflowcollector.storage.FlowStore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(ClickHouseProperties.class)
public class ClickHouseStorageConfiguration {

    @Bean
    @ConditionalOnProperty(prefix = "clickhouse", name = "enabled", havingValue = "true", matchIfMissing = true)
    FlowStore clickHouseFlowStore(ClickHouseProperties properties) {
        return new ClickHouseFlowStore(properties);
    }
}
