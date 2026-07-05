package com.kien.networkflowcollector.storage.clickhouse;

import com.kien.networkflowcollector.metrics.MeteredFlowStore;
import com.kien.networkflowcollector.metrics.PipelineMetrics;
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
    FlowStore clickHouseFlowStore(ClickHouseProperties properties, PipelineMetrics metrics) {
        ClickHouseFlowStore store = new ClickHouseFlowStore(properties);
        if (properties.isCleanOnStart()) {
            store.truncate();
        }
        return new MeteredFlowStore(store, metrics);
    }
}
