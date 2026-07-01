package com.kien.networkflowcollector.plugins.zeek;

import static org.assertj.core.api.Assertions.assertThat;

import com.kien.networkflowcollector.spi.FlowCollector;
import com.kien.networkflowcollector.spi.FlowNormalizer;
import java.util.ServiceLoader;
import org.junit.jupiter.api.Test;

class ZeekCollectorTest {

    @Test
    void collectorAdvertisesZeekConnSupport() {
        ZeekCollector collector = new ZeekCollector();

        assertThat(collector.type()).isEqualTo("zeek");
        assertThat(collector.supportedSourceTypes()).containsExactly("zeek-conn");
    }

    @Test
    void serviceLoaderDiscoversZeekCollectorAndNormalizer() {
        assertThat(ServiceLoader.load(FlowCollector.class).stream().map(ServiceLoader.Provider::type))
                .contains(ZeekCollector.class);
        assertThat(ServiceLoader.load(FlowNormalizer.class).stream().map(ServiceLoader.Provider::type))
                .contains(ZeekConnNormalizer.class);
    }
}
