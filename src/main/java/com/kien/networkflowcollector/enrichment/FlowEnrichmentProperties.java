package com.kien.networkflowcollector.enrichment;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "nfc.enrichment")
public class FlowEnrichmentProperties {

    private boolean enabled = true;
    private String prefixes = PrefixFlowEnrichmentProvider.DEFAULT_PREFIXES;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getPrefixes() {
        return prefixes;
    }

    public void setPrefixes(String prefixes) {
        this.prefixes =
                prefixes == null || prefixes.isBlank()
                        ? PrefixFlowEnrichmentProvider.DEFAULT_PREFIXES
                        : prefixes;
    }
}
