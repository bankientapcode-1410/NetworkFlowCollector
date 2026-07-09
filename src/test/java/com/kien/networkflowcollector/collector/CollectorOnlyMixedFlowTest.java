package com.kien.networkflowcollector.collector;

import static org.assertj.core.api.Assertions.assertThat;

import com.kien.networkflowcollector.kafka.PublishBackpressureException;
import com.kien.networkflowcollector.plugins.netflow.NetFlowCollector;
import com.kien.networkflowcollector.plugins.suricata.SuricataCollector;
import com.kien.networkflowcollector.plugins.zeek.ZeekCollector;
import com.kien.networkflowcollector.spi.CollectorConfig;
import com.kien.networkflowcollector.spi.FlowPublisher;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.CleanupMode;
import org.junit.jupiter.api.io.TempDir;

class CollectorOnlyMixedFlowTest {

    @TempDir(cleanup = CleanupMode.NEVER)
    private Path tempDir;

    @Test
    void collectorsSeparateRandomMixedFlowSourcesWithoutKafkaOrStorage() throws Exception {
        Path suricataLog = tempDir.resolve("suricata-eve.json");
        Path zeekLog = tempDir.resolve("conn.log");
        int netflowPort = freeUdpPort();

        Random random = new Random(2606L);
        List<Source> sources = mixedSources(random, 45);
        Map<Source, Integer> expectedCounts = new EnumMap<>(Source.class);
        List<String> suricataLines = new ArrayList<>();
        List<String> zeekLines = new ArrayList<>();

        for (int index = 0; index < sources.size(); index++) {
            Source source = sources.get(index);
            expectedCounts.merge(source, 1, Integer::sum);
            switch (source) {
                case SURICATA -> suricataLines.add(suricataFlow(index, random));
                case ZEEK -> zeekLines.add(zeekConn(index, random));
                case NETFLOW -> {
                    // NetFlow is sent after the UDP collector starts.
                }
            }
        }

        Files.writeString(suricataLog, String.join(System.lineSeparator(), suricataLines) + System.lineSeparator());
        Files.writeString(zeekLog, String.join(System.lineSeparator(), zeekLines) + System.lineSeparator());

        InMemoryPublisher publisher = new InMemoryPublisher();
        SuricataCollector suricata = new SuricataCollector();
        ZeekCollector zeek = new ZeekCollector();
        NetFlowCollector netflow = new NetFlowCollector();
        List<com.kien.networkflowcollector.spi.FlowCollector> started = new ArrayList<>();

        try {
            suricata.init(textConfig(suricataLog), publisher);
            suricata.start();
            started.add(suricata);

            zeek.init(textConfig(zeekLog), publisher);
            zeek.start();
            started.add(zeek);

            netflow.init(
                    new CollectorConfig(
                            true,
                            Map.of(
                                    "bindAddress", "127.0.0.1",
                                    "port", netflowPort,
                                    "receiveBufferBytes", 262_144)),
                    publisher);
            netflow.start();
            started.add(netflow);

            sendNetFlowPackets(netflowPort, expectedCounts.getOrDefault(Source.NETFLOW, 0));

            awaitRecordCount(publisher, sources.size(), Duration.ofSeconds(5));

            Map<String, Long> actualCounts =
                    publisher.snapshot().stream()
                            .collect(Collectors.groupingBy(RawFlowRecord::sourceType, Collectors.counting()));

            assertThat(actualCounts.keySet())
                    .containsExactlyInAnyOrder("suricata-flow", "zeek-conn", "netflow-v5");
            assertThat(actualCounts)
                    .containsEntry("suricata-flow", expectedCounts.get(Source.SURICATA).longValue())
                    .containsEntry("zeek-conn", expectedCounts.get(Source.ZEEK).longValue())
                    .containsEntry("netflow-v5", expectedCounts.get(Source.NETFLOW).longValue());
        } finally {
            for (int index = started.size() - 1; index >= 0; index--) {
                started.get(index).stop();
            }
        }
    }

    @Test
    void netflowCollectorRetriesTransientPublishBackpressure() throws Exception {
        int netflowPort = freeUdpPort();
        BackpressureThenSuccessPublisher publisher = new BackpressureThenSuccessPublisher();
        NetFlowCollector netflow = new NetFlowCollector();

        try {
            netflow.init(
                    new CollectorConfig(
                            true,
                            Map.of(
                                    "bindAddress", "127.0.0.1",
                                    "port", netflowPort,
                                    "workerThreads", 1,
                                    "packetQueueCapacity", 16,
                                    "publishBackpressureRetryAttempts", 3,
                                    "publishBackpressureRetryDelayMs", 1)),
                    publisher);
            netflow.start();

            sendNetFlowPackets(netflowPort, 1);

            assertThat(publisher.awaitRecord(Duration.ofSeconds(5))).isTrue();
            assertThat(publisher.attempts()).isEqualTo(2);
            assertThat(awaitHealthMessage(netflow, Duration.ofSeconds(5)))
                    .contains("records=1")
                    .contains("publish_errors=0")
                    .contains("publish_backpressure_retries=1");
        } finally {
            netflow.stop();
        }
    }

    private static CollectorConfig textConfig(Path path) {
        return new CollectorConfig(
                true,
                Map.of(
                        "paths", List.of(path.toString()),
                        "pollIntervalMs", 25L,
                        "exporterIp", "test-sensor"));
    }

    private static List<Source> mixedSources(Random random, int count) {
        List<Source> sources = new ArrayList<>(List.of(Source.SURICATA, Source.ZEEK, Source.NETFLOW));
        for (int index = sources.size(); index < count; index++) {
            Source[] values = Source.values();
            sources.add(values[random.nextInt(values.length)]);
        }
        java.util.Collections.shuffle(sources, random);
        return sources;
    }

    private static String suricataFlow(int index, Random random) {
        String protocol = protocol(random).toUpperCase(Locale.ROOT);
        int srcPort = "ICMP".equals(protocol) ? 0 : 20_000 + index;
        int dstPort = "ICMP".equals(protocol) ? 0 : 443;
        return String.format(
                Locale.ROOT,
                "{\"timestamp\":\"2026-07-04T12:00:%02dZ\",\"event_type\":\"flow\","
                        + "\"src_ip\":\"192.168.1.%d\",\"src_port\":%d,"
                        + "\"dest_ip\":\"10.0.0.%d\",\"dest_port\":%d,"
                        + "\"proto\":\"%s\",\"flow_id\":%d,"
                        + "\"flow\":{\"pkts_toserver\":%d,\"pkts_toclient\":%d,"
                        + "\"bytes_toserver\":%d,\"bytes_toclient\":%d,"
                        + "\"start\":\"2026-07-04T12:00:%02dZ\","
                        + "\"end\":\"2026-07-04T12:00:%02dZ\","
                        + "\"age\":1,\"state\":\"established\",\"reason\":\"timeout\",\"alerted\":false}}",
                index % 60,
                10 + index,
                srcPort,
                40 + index,
                dstPort,
                protocol,
                1_000_000 + index,
                1 + random.nextInt(20),
                1 + random.nextInt(20),
                100 + random.nextInt(2000),
                100 + random.nextInt(2000),
                index % 60,
                (index + 1) % 60);
    }

    private static String zeekConn(int index, Random random) {
        String protocol = protocol(random);
        int srcPort = "icmp".equals(protocol) ? 0 : 30_000 + index;
        int dstPort = "icmp".equals(protocol) ? 0 : 53;
        return String.format(
                Locale.ROOT,
                "{\"_path\":\"conn\",\"ts\":1783180800.%03d,\"uid\":\"Cmix%d\","
                        + "\"id.orig_h\":\"172.16.1.%d\",\"id.orig_p\":%d,"
                        + "\"id.resp_h\":\"10.10.0.%d\",\"id.resp_p\":%d,"
                        + "\"proto\":\"%s\",\"duration\":0.%03d,"
                        + "\"orig_bytes\":%d,\"resp_bytes\":%d,"
                        + "\"orig_pkts\":%d,\"resp_pkts\":%d}",
                index,
                index,
                10 + index,
                srcPort,
                40 + index,
                dstPort,
                protocol,
                100 + random.nextInt(800),
                100 + random.nextInt(2000),
                100 + random.nextInt(2000),
                1 + random.nextInt(20),
                1 + random.nextInt(20));
    }

    private static String protocol(Random random) {
        return switch (random.nextInt(3)) {
            case 0 -> "tcp";
            case 1 -> "udp";
            default -> "icmp";
        };
    }

    private static void sendNetFlowPackets(int port, int count) throws IOException {
        InetAddress target = InetAddress.getByName("127.0.0.1");
        try (DatagramSocket socket = new DatagramSocket()) {
            for (int index = 0; index < count; index++) {
                byte[] payload = netflowV5Packet(index);
                socket.send(new DatagramPacket(payload, payload.length, target, port));
            }
        }
    }

    private static byte[] netflowV5Packet(int sequence) {
        ByteBuffer buffer = ByteBuffer.allocate(24 + 48).order(ByteOrder.BIG_ENDIAN);
        buffer.putShort((short) 5);
        buffer.putShort((short) 1);
        buffer.putInt(100_000 + sequence);
        buffer.putInt(1_783_180_800);
        buffer.putInt(0);
        buffer.putInt(sequence);
        buffer.put((byte) 0);
        buffer.put((byte) 0);
        buffer.putShort((short) 0);

        buffer.putInt(0x0A000001 + sequence);
        buffer.putInt(0xC0A80101 + sequence);
        buffer.putInt(0);
        buffer.putShort((short) 1);
        buffer.putShort((short) 2);
        buffer.putInt(10 + sequence);
        buffer.putInt(1024 + sequence);
        buffer.putInt(98_000 + sequence);
        buffer.putInt(100_000 + sequence);
        buffer.putShort((short) (40_000 + sequence));
        buffer.putShort((short) 443);
        buffer.put((byte) 0);
        buffer.put((byte) 0x12);
        buffer.put((byte) 6);
        buffer.put((byte) 0);
        buffer.putShort((short) 0);
        buffer.putShort((short) 0);
        buffer.put((byte) 24);
        buffer.put((byte) 24);
        buffer.putShort((short) 0);
        return buffer.array();
    }

    private static int freeUdpPort() throws IOException {
        try (DatagramSocket socket = new DatagramSocket(0, InetAddress.getByName("127.0.0.1"))) {
            return socket.getLocalPort();
        }
    }

    private static void awaitRecordCount(
            InMemoryPublisher publisher, int expectedCount, Duration timeout) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (System.nanoTime() < deadline) {
            if (publisher.size() >= expectedCount) {
                return;
            }
            TimeUnit.MILLISECONDS.sleep(25);
        }
        assertThat(publisher.snapshot()).hasSize(expectedCount);
    }

    private static String awaitHealthMessage(NetFlowCollector netflow, Duration timeout) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        String message = netflow.health().message();
        while (System.nanoTime() < deadline) {
            message = netflow.health().message();
            if (message.contains("records=1")
                    && message.contains("publish_errors=0")
                    && message.contains("publish_backpressure_retries=1")) {
                return message;
            }
            TimeUnit.MILLISECONDS.sleep(25);
        }
        return message;
    }

    private enum Source {
        SURICATA,
        ZEEK,
        NETFLOW
    }

    private static final class InMemoryPublisher implements FlowPublisher {

        private final CopyOnWriteArrayList<RawFlowRecord> records = new CopyOnWriteArrayList<>();

        @Override
        public CompletionStage<Void> publish(RawFlowRecord record) {
            records.add(record);
            return CompletableFuture.completedFuture(null);
        }

        int size() {
            return records.size();
        }

        List<RawFlowRecord> snapshot() {
            return List.copyOf(records);
        }
    }

    private static final class BackpressureThenSuccessPublisher implements FlowPublisher {

        private final AtomicInteger attempts = new AtomicInteger();
        private final CountDownLatch published = new CountDownLatch(1);

        @Override
        public CompletionStage<Void> publish(RawFlowRecord record) {
            if (attempts.incrementAndGet() == 1) {
                return CompletableFuture.failedFuture(new PublishBackpressureException("no permits"));
            }
            published.countDown();
            return CompletableFuture.completedFuture(null);
        }

        boolean awaitRecord(Duration timeout) throws InterruptedException {
            return published.await(timeout.toMillis(), TimeUnit.MILLISECONDS);
        }

        int attempts() {
            return attempts.get();
        }
    }
}
