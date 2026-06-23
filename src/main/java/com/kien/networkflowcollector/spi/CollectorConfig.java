package com.kien.networkflowcollector.spi;

import java.util.Map;

public record CollectorConfig(boolean enabled, Map<String, Object> properties) {

    public CollectorConfig {
        properties = Map.copyOf(properties == null ? Map.of() : properties);
    }
}
