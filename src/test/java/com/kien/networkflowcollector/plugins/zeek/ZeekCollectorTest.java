package com.kien.networkflowcollector.plugins.zeek;

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

    // Verifies an enabled Zeek collector fails fast when no log path is configured.
    @Test
    void rejectsStartWithoutConfiguredLogPaths() {
        ZeekCollector collector = new ZeekCollector();
        collector.init(new CollectorConfig(true, Map.of()), record -> CompletableFuture.completedFuture(null));

        assertThatThrownBy(collector::start)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("no Zeek log paths configured");
        assertThat(collector.health().status()).isEqualTo(CollectorStatus.DOWN);
    }

    // Verifies Zeek decode exceptions are reported through degraded collector health.
    @Test
    void recordsDecodeFailureAsDegradedHealth(@TempDir(cleanup = CleanupMode.NEVER) Path tempDir) throws Exception {
        Path log = tempDir.resolve("conn.log");
        Files.writeString(log, "1700000000.0\tCbefore-metadata" + System.lineSeparator());
        ZeekCollector collector = startedCollector(log, record -> CompletableFuture.completedFuture(null));

        try {
            String healthMessage = awaitHealthMessage(collector, "failed to decode Zeek log line");

            assertThat(collector.health().status()).isEqualTo(CollectorStatus.DEGRADED);
            assertThat(healthMessage).contains("decode_errors=1");
        } finally {
            collector.stop();
        }
    }

    // Verifies Zeek publish exceptions are reported through degraded collector health.
    @Test
    void recordsPublishFailureAsDegradedHealth(@TempDir(cleanup = CleanupMode.NEVER) Path tempDir) throws Exception {
        Path log = tempDir.resolve("conn.log");
        Files.writeString(log, zeekConnJsonLine() + System.lineSeparator());
        ZeekCollector collector =
                startedCollector(
                        log,
                        record -> {
                            throw new IllegalStateException("publisher down");
                        });

        try {
            String healthMessage = awaitHealthMessage(collector, "failed to publish Zeek record");

            assertThat(collector.health().status()).isEqualTo(CollectorStatus.DEGRADED);
            assertThat(healthMessage).contains("publish_errors=1");
        } finally {
            collector.stop();
        }
    }

    private static ZeekCollector startedCollector(Path log, FlowPublisher publisher) {
        ZeekCollector collector = new ZeekCollector();
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
                        "exporterIp", "zeek-test"));
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

    private static String zeekConnJsonLine() {
        return """
                {"_path":"conn","ts":1700000000.5,"uid":"Cjson","id.orig_h":"2001:db8::1","id.orig_p":5353,"id.resp_h":"2001:db8::2","id.resp_p":53,"proto":"udp","duration":0.25,"orig_bytes":10,"resp_bytes":20,"orig_pkts":1,"resp_pkts":2}
                """
                .strip();
    }
}
