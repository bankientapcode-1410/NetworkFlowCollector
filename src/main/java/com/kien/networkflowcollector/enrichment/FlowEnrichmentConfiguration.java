package com.kien.networkflowcollector.enrichment;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(FlowEnrichmentProperties.class)
public class FlowEnrichmentConfiguration {

    @Bean
    FlowEnrichmentProvider flowEnrichmentProvider(FlowEnrichmentProperties properties) {
        if (!properties.isEnabled()) {
            return FlowEnrichmentProvider.noop();
        }
        return PrefixFlowEnrichmentProvider.fromSpec(properties.getPrefixes());
    }
}
