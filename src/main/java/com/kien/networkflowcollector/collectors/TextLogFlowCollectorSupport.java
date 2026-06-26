package com.kien.networkflowcollector.collectors;

import com.kien.networkflowcollector.spi.CollectorConfig;
import com.kien.networkflowcollector.spi.CollectorHealth;
import com.kien.networkflowcollector.spi.CollectorStatus;
import com.kien.networkflowcollector.spi.FlowCollector;
import com.kien.networkflowcollector.spi.FlowPublisher;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.io.IOException;
import java.lang.reflect.Array;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public abstract class TextLogFlowCollectorSupport implements FlowCollector {

    private static final long DEFAULT_POLL_INTERVAL_MS = 1_000L;

    private final String type;
    private final Set<String> supportedSourceTypes;
    private final String defaultExporterIp;
    private final String displayName;
    private final AtomicLong linesReceived = new AtomicLong();
    private final AtomicLong recordsPublished = new AtomicLong();
    private final AtomicLong decodeErrors = new AtomicLong();
    private final AtomicLong publishErrors = new AtomicLong();
    private final AtomicLong readErrors = new AtomicLong();

    private volatile CollectorConfig config = new CollectorConfig(false, Map.of());
    private volatile FlowPublisher publisher;
    private volatile ScheduledExecutorService executor;
    private volatile CollectorStatus status = CollectorStatus.STOPPED;
    private volatile String message = "not initialized";
    private volatile Instant lastRecordAt;
    private volatile List<Path> paths = List.of();
    private volatile String exporterIp;
    private volatile long pollIntervalMs = DEFAULT_POLL_INTERVAL_MS;
    private volatile boolean startAtEnd;
    private final Map<Path, Long> offsets = new java.util.concurrent.ConcurrentHashMap<>();

    protected TextLogFlowCollectorSupport(
            String type, Set<String> supportedSourceTypes, String defaultExporterIp, String displayName) {
        this.type = Objects.requireNonNull(type, "type");
        this.supportedSourceTypes = Set.copyOf(Objects.requireNonNull(supportedSourceTypes, "supportedSourceTypes"));
        this.defaultExporterIp = Objects.requireNonNull(defaultExporterIp, "defaultExporterIp");
        this.displayName = Objects.requireNonNull(displayName, "displayName");
        this.exporterIp = defaultExporterIp;
    }

    @Override
    public String type() {
        return type;
    }

    @Override
    public Set<String> supportedSourceTypes() {
        return supportedSourceTypes;
    }

    @Override
    public synchronized void init(CollectorConfig config, FlowPublisher publisher) {
        this.config = config == null ? new CollectorConfig(true, Map.of()) : config;
        this.publisher = publisher;
        offsets.clear();

        Map<String, Object> properties = this.config.properties();
        this.paths = pathsProperty(properties);
        this.exporterIp = stringProperty(properties, "exporterIp", "exporter_ip", defaultExporterIp);
        this.pollIntervalMs = longProperty(properties, "pollIntervalMs", "poll_interval_ms", DEFAULT_POLL_INTERVAL_MS);
        this.startAtEnd = booleanProperty(properties, "startAtEnd", "start_at_end", false);

        if (!this.config.enabled()) {
            status = CollectorStatus.STOPPED;
            message = "collector disabled";
            return;
        }
        Objects.requireNonNull(publisher, "publisher");
        if (startAtEnd) {
            initializeOffsetsAtEnd();
        }
        status = CollectorStatus.STOPPED;
        message = paths.isEmpty() ? "initialized with no " + displayName + " log paths" : "initialized for " + paths;
    }

    @Override
    public synchronized void start() {
        if (!config.enabled()) {
            status = CollectorStatus.STOPPED;
            message = "collector disabled";
            return;
        }
        Objects.requireNonNull(publisher, "publisher");
        if (paths.isEmpty()) {
            status = CollectorStatus.DOWN;
            message = "no " + displayName + " log paths configured";
            throw new IllegalStateException(message);
        }
        if (executor != null && !executor.isShutdown()) {
            return;
        }

        status = CollectorStatus.STARTING;
        message = "polling " + displayName + " logs " + paths;
        ScheduledExecutorService newExecutor =
                Executors.newSingleThreadScheduledExecutor(
                        runnable -> {
                            Thread thread = new Thread(runnable, type + "-collector");
                            thread.setDaemon(true);
                            return thread;
                        });
        executor = newExecutor;
        newExecutor.scheduleWithFixedDelay(this::pollAll, 0, pollIntervalMs, TimeUnit.MILLISECONDS);
        status = CollectorStatus.UP;
        message = "polling " + displayName + " logs " + paths;
    }

    @Override
    public synchronized void stop() {
        ScheduledExecutorService currentExecutor = executor;
        executor = null;
        if (currentExecutor != null) {
            currentExecutor.shutdownNow();
        }
        status = CollectorStatus.STOPPED;
        message = "stopped";
    }

    @Override
    public CollectorHealth health() {
        CollectorStatus currentStatus = status;
        if (currentStatus == CollectorStatus.UP
                && (decodeErrors.get() > 0 || publishErrors.get() > 0 || readErrors.get() > 0)) {
            currentStatus = CollectorStatus.DEGRADED;
        }
        String healthMessage =
                message
                        + " lines="
                        + linesReceived.get()
                        + " records="
                        + recordsPublished.get()
                        + " decode_errors="
                        + decodeErrors.get()
                        + " publish_errors="
                        + publishErrors.get()
                        + " read_errors="
                        + readErrors.get();
        return new CollectorHealth(currentStatus, healthMessage, Instant.now(), lastRecordAt);
    }

    protected abstract Optional<RawFlowRecord> decodeLine(
            Path path, String line, String exporterIp, Instant receivedAt);

    private void pollAll() {
        for (Path path : paths) {
            poll(path);
        }
    }

    private void poll(Path path) {
        if (!Files.exists(path)) {
            readErrors.incrementAndGet();
            message = displayName + " log path does not exist: " + path;
            return;
        }

        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            long size = channel.size();
            long offset = offsets.getOrDefault(path, 0L);
            if (size < offset) {
                offset = 0L;
            }
            long bytesToRead = size - offset;
            if (bytesToRead <= 0) {
                offsets.put(path, size);
                return;
            }
            if (bytesToRead > Integer.MAX_VALUE) {
                readErrors.incrementAndGet();
                offsets.put(path, size);
                message = displayName + " log read window too large for " + path + ": " + bytesToRead + " bytes";
                return;
            }

            ByteBuffer buffer = ByteBuffer.allocate((int) bytesToRead);
            channel.position(offset);
            while (buffer.hasRemaining() && channel.read(buffer) > 0) {
                // Read the current append window.
            }
            buffer.flip();
            offsets.put(path, offset + buffer.limit());
            decodeLines(path, StandardCharsets.UTF_8.decode(buffer).toString());
        } catch (IOException e) {
            readErrors.incrementAndGet();
            message = "failed to read " + displayName + " log " + path + ": " + e.getMessage();
        }
    }

    private void decodeLines(Path path, String text) {
        Instant receivedAt = Instant.now();
        for (String line : text.split("\\R", -1)) {
            if (line.isEmpty()) {
                continue;
            }
            linesReceived.incrementAndGet();
            try {
                Optional<RawFlowRecord> record = decodeLine(path, line, exporterIp, receivedAt);
                record.ifPresent(this::publish);
                if (record.isPresent()) {
                    lastRecordAt = receivedAt;
                }
            } catch (RuntimeException e) {
                decodeErrors.incrementAndGet();
                message = "failed to decode " + displayName + " log line from " + path + ": " + e.getMessage();
            }
        }
    }

    private void publish(RawFlowRecord record) {
        try {
            CompletionStage<Void> completion = publisher.publish(record);
            if (completion == null) {
                recordsPublished.incrementAndGet();
                return;
            }
            completion.whenComplete(
                    (ignored, error) -> {
                        if (error == null) {
                            recordsPublished.incrementAndGet();
                        } else {
                            publishErrors.incrementAndGet();
                            message = "failed to publish " + displayName + " record: " + error.getMessage();
                        }
                    });
        } catch (RuntimeException e) {
            publishErrors.incrementAndGet();
            message = "failed to publish " + displayName + " record: " + e.getMessage();
        }
    }

    private void initializeOffsetsAtEnd() {
        for (Path path : paths) {
            try {
                if (Files.exists(path)) {
                    offsets.put(path, Files.size(path));
                }
            } catch (IOException e) {
                readErrors.incrementAndGet();
                message = "failed to initialize " + displayName + " offset for " + path + ": " + e.getMessage();
            }
        }
    }

    private static List<Path> pathsProperty(Map<String, Object> properties) {
        Object value = properties.get("paths");
        if (value == null) {
            value = properties.get("logPaths");
        }
        if (value == null) {
            value = properties.get("log_paths");
        }
        if (value == null) {
            value = properties.get("path");
        }
        if (value == null) {
            return List.of();
        }
        if (value instanceof Collection<?> collection) {
            return collection.stream().map(item -> Path.of(item.toString())).toList();
        }
        if (value.getClass().isArray()) {
            int length = Array.getLength(value);
            List<Path> out = new ArrayList<>(length);
            for (int i = 0; i < length; i++) {
                Object item = Array.get(value, i);
                out.add(Path.of(item.toString()));
            }
            return out;
        }
        String[] pieces = value.toString().split("[,;]");
        List<Path> out = new ArrayList<>(pieces.length);
        for (String piece : pieces) {
            if (!piece.isBlank()) {
                out.add(Path.of(piece.trim()));
            }
        }
        return List.copyOf(out);
    }

    private static String stringProperty(
            Map<String, Object> properties, String primaryKey, String aliasKey, String defaultValue) {
        Object value = properties.get(primaryKey);
        if (value == null) {
            value = properties.get(aliasKey);
        }
        return value == null ? defaultValue : value.toString();
    }

    private static long longProperty(
            Map<String, Object> properties, String primaryKey, String aliasKey, long defaultValue) {
        Object value = properties.get(primaryKey);
        if (value == null) {
            value = properties.get(aliasKey);
        }
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Number number) {
            return number.longValue();
        }
        return Long.parseLong(value.toString());
    }

    private static boolean booleanProperty(
            Map<String, Object> properties, String primaryKey, String aliasKey, boolean defaultValue) {
        Object value = properties.get(primaryKey);
        if (value == null) {
            value = properties.get(aliasKey);
        }
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Boolean bool) {
            return bool;
        }
        return Boolean.parseBoolean(value.toString());
    }
}
