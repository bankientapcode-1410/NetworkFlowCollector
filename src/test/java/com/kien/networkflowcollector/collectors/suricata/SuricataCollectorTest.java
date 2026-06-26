package com.kien.networkflowcollector.collectors.suricata;

import static org.assertj.core.api.Assertions.assertThat;

import com.kien.networkflowcollector.spi.FlowCollector;
import com.kien.networkflowcollector.spi.FlowNormalizer;
import java.util.ServiceLoader;
import org.junit.jupiter.api.Test;

class SuricataCollectorTest {

    @Test
    void collectorAdvertisesSuricataFlowSupport() {
        SuricataCollector collector = new SuricataCollector();

        assertThat(collector.type()).isEqualTo("suricata");
        assertThat(collector.supportedSourceTypes()).containsExactly("suricata-flow");
    }

    @Test
    void serviceLoaderDiscoversSuricataCollectorAndNormalizer() {
        assertThat(ServiceLoader.load(FlowCollector.class).stream().map(ServiceLoader.Provider::type))
                .contains(SuricataCollector.class);
        assertThat(ServiceLoader.load(FlowNormalizer.class).stream().map(ServiceLoader.Provider::type))
                .contains(SuricataFlowNormalizer.class);
    }
}
