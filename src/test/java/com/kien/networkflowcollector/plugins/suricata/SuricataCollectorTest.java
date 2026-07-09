package com.kien.networkflowcollector.plugins.suricata;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.kien.networkflowcollector.spi.CollectorConfig;
import com.kien.networkflowcollector.spi.CollectorStatus;
import com.kien.networkflowcollector.spi.FlowCollector;
import com.kien.networkflowcollector.spi.FlowNormalizer;
import com.kien.networkflowcollector.spi.FlowPublisher;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.CleanupMode;
import org.junit.jupiter.api.io.TempDir;

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

    // Verifies an enabled Suricata collector fails fast when no log path is configured.
    @Test
    void rejectsStartWithoutConfiguredLogPaths() {
        SuricataCollector collector = new SuricataCollector();
        collector.init(new CollectorConfig(true, Map.of()), record -> CompletableFuture.completedFuture(null));

        assertThatThrownBy(collector::start)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("no Suricata log paths configured");
        assertThat(collector.health().status()).isEqualTo(CollectorStatus.DOWN);
    }

    // Verifies Suricata decode exceptions are reported through degraded collector health.
    @Test
    void recordsDecodeFailureAsDegradedHealth(@TempDir(cleanup = CleanupMode.NEVER) Path tempDir) throws Exception {
        Path log = tempDir.resolve("eve.json");
        Files.writeString(log, "not-json" + System.lineSeparator());
        SuricataCollector collector =
                startedCollector(log, record -> CompletableFuture.completedFuture(null));

        try {
            String healthMessage = awaitHealthMessage(collector, "failed to decode Suricata log line");

            assertThat(collector.health().status()).isEqualTo(CollectorStatus.DEGRADED);
            assertThat(healthMessage).contains("decode_errors=1");
        } finally {
            collector.stop();
        }
    }

    // Verifies Suricata publish exceptions are reported through degraded collector health.
    @Test
    void recordsPublishFailureAsDegradedHealth(@TempDir(cleanup = CleanupMode.NEVER) Path tempDir) throws Exception {
        Path log = tempDir.resolve("eve.json");
        Files.writeString(log, SuricataEveDecoderTest.flowEvent() + System.lineSeparator());
        SuricataCollector collector =
                startedCollector(
                        log,
                        record -> {
                            throw new IllegalStateException("publisher down");
                        });

        try {
            String healthMessage = awaitHealthMessage(collector, "failed to publish Suricata record");

            assertThat(collector.health().status()).isEqualTo(CollectorStatus.DEGRADED);
            assertThat(healthMessage).contains("publish_errors=1");
        } finally {
            collector.stop();
        }
    }

    private static SuricataCollector startedCollector(Path log, FlowPublisher publisher) {
        SuricataCollector collector = new SuricataCollector();
        collector.init(textConfig(log), publisher);
        collector.start();
        return collector;
    }

    private static CollectorConfig textConfig(Path log) {
        return new CollectorConfig(
                true,
                Map.of(
                        "paths", List.of(log.toString()),
                        "pollIntervalMs", 10L,
                        "exporterIp", "suricata-test"));
    }

    private static String awaitHealthMessage(FlowCollector collector, String messagePart) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
        String message = collector.health().message();
        while (System.nanoTime() < deadline) {
            message = collector.health().message();
            if (message.contains(messagePart)) {
                return message;
            }
            TimeUnit.MILLISECONDS.sleep(25);
        }
        assertThat(message).contains(messagePart);
        return message;
    }
}
