package com.kien.networkflowcollector.collector;

import com.kien.networkflowcollector.spi.CollectorConfig;
import java.util.LinkedHashMap;
import java.util.Map;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "nfc.collectors")
public class CollectorProperties {

    private boolean enabled = true;
    private final Map<String, CollectorSpec> configs = new LinkedHashMap<>();

    CollectorConfig configFor(String collectorType) {
        CollectorSpec spec = configs.getOrDefault(collectorType, new CollectorSpec());
        return new CollectorConfig(enabled && spec.enabled, spec.properties);
    }

    @Getter
    public static class CollectorSpec {

        @Setter
        private boolean enabled;
        private Map<String, Object> properties = new LinkedHashMap<>();

        public void setProperties(Map<String, Object> properties) {
            this.properties = properties == null ? new LinkedHashMap<>() : new LinkedHashMap<>(properties);
        }
    }
}
