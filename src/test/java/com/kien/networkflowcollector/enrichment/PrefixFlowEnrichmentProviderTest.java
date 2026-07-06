package com.kien.networkflowcollector.enrichment;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class PrefixFlowEnrichmentProviderTest {

    @Test
    void lookupReturnsLongestMatchingPrefix() {
        PrefixFlowEnrichmentProvider provider =
                PrefixFlowEnrichmentProvider.fromSpec(
                        "8.8.8.0/24,US,15169,Google LLC;8.8.8.8/32,CA,64500,Override Org");

        assertThat(provider.lookup("8.8.8.8"))
                .hasValue(new IpEnrichment("CA", 64_500L, "Override Org"));
        assertThat(provider.lookup("8.8.8.9"))
                .hasValue(new IpEnrichment("US", 15_169L, "Google LLC"));
    }

    @Test
    void lookupUnknownOrPrivateIpReturnsEmpty() {
        PrefixFlowEnrichmentProvider provider =
                PrefixFlowEnrichmentProvider.fromSpec("8.8.8.0/24,US,15169,Google LLC");

        assertThat(provider.lookup("192.168.1.10")).isEmpty();
        assertThat(provider.lookup("not-an-ip")).isEmpty();
    }

    @Test
    void invalidPrefixSpecFailsFast() {
        assertThatThrownBy(() -> PrefixFlowEnrichmentProvider.fromSpec("not-a-cidr,US"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
