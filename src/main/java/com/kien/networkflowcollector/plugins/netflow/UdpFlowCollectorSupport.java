package com.kien.networkflowcollector.plugins.netflow;

import com.kien.networkflowcollector.kafka.PublishBackpressureException;
import com.kien.networkflowcollector.spi.CollectorConfig;
import com.kien.networkflowcollector.spi.CollectorHealth;
import com.kien.networkflowcollector.spi.CollectorStatus;
import com.kien.networkflowcollector.spi.FlowCollector;
import com.kien.networkflowcollector.spi.FlowPublisher;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.DatagramPacket;
import io.netty.channel.socket.nio.NioDatagramChannel;
import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public abstract class UdpFlowCollectorSupport implements FlowCollector {

    private static final String DEFAULT_BIND_ADDRESS = "0.0.0.0";
    private static final int DEFAULT_RECEIVE_BUFFER_BYTES = 8_388_608;
    private static final int DEFAULT_PACKET_QUEUE_CAPACITY = 8_192;
    private static final int DEFAULT_PUBLISH_BACKPRESSURE_RETRY_ATTEMPTS = 20;
    private static final int DEFAULT_PUBLISH_BACKPRESSURE_RETRY_DELAY_MS = 5;

    private final String type;
    private final Set<String> supportedSourceTypes;
    private final int defaultPort;
    private final AtomicLong packetsReceived = new AtomicLong();
    private final AtomicLong packetsDropped = new AtomicLong();
    private final AtomicLong recordsPublished = new AtomicLong();
    private final AtomicLong decodeErrors = new AtomicLong();
    private final AtomicLong publishErrors = new AtomicLong();
    private final AtomicLong publishBackpressureRetries = new AtomicLong();

    private volatile CollectorConfig config = new CollectorConfig(false, Map.of());
    private volatile FlowPublisher publisher;
    private volatile EventLoopGroup group;
    private volatile Channel channel;
    private volatile ExecutorService workerPool;
    private volatile BlockingQueue<UdpPacketWork> packetQueue;
    private volatile boolean workersRunning;
    private volatile CollectorStatus status = CollectorStatus.STOPPED;
    private volatile String message = "not initialized";
    private volatile Instant lastRecordAt;
    private volatile String bindAddress = DEFAULT_BIND_ADDRESS;
    private volatile int port;
    private volatile int receiveBufferBytes = DEFAULT_RECEIVE_BUFFER_BYTES;
    private volatile int packetQueueCapacity = DEFAULT_PACKET_QUEUE_CAPACITY;
    private volatile int workerThreads = defaultWorkerThreads();
    private volatile int publishBackpressureRetryAttempts = DEFAULT_PUBLISH_BACKPRESSURE_RETRY_ATTEMPTS;
    private volatile int publishBackpressureRetryDelayMs = DEFAULT_PUBLISH_BACKPRESSURE_RETRY_DELAY_MS;

    protected UdpFlowCollectorSupport(String type, Set<String> supportedSourceTypes, int defaultPort) {
        this.type = Objects.requireNonNull(type, "type");
        this.supportedSourceTypes = Set.copyOf(Objects.requireNonNull(supportedSourceTypes, "supportedSourceTypes"));
        this.defaultPort = defaultPort;
        this.port = defaultPort;
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

        Map<String, Object> properties = this.config.properties();
        this.bindAddress = stringProperty(properties, "bindAddress", "bind_address", DEFAULT_BIND_ADDRESS);
        this.port = intProperty(properties, "port", defaultPort);
        this.receiveBufferBytes =
                intProperty(
                        properties,
                        "receiveBufferBytes",
                        "receive_buffer_bytes",
                        DEFAULT_RECEIVE_BUFFER_BYTES);
        this.packetQueueCapacity =
                intProperty(
                        properties,
                        "packetQueueCapacity",
                        "packet_queue_capacity",
                        DEFAULT_PACKET_QUEUE_CAPACITY);
        this.workerThreads = intProperty(properties, "workerThreads", "worker_threads", defaultWorkerThreads());
        this.publishBackpressureRetryAttempts =
                intProperty(
                        properties,
                        "publishBackpressureRetryAttempts",
                        "publish_backpressure_retry_attempts",
                        DEFAULT_PUBLISH_BACKPRESSURE_RETRY_ATTEMPTS);
        this.publishBackpressureRetryDelayMs =
                intProperty(
                        properties,
                        "publishBackpressureRetryDelayMs",
                        "publish_backpressure_retry_delay_ms",
                        DEFAULT_PUBLISH_BACKPRESSURE_RETRY_DELAY_MS);

        if (!this.config.enabled()) {
            this.status = CollectorStatus.STOPPED;
            this.message = "collector disabled";
            return;
        }
        Objects.requireNonNull(publisher, "publisher");
        this.status = CollectorStatus.STOPPED;
        this.message = "initialized on " + bindAddress + ":" + port;
    }

    @Override
    public synchronized void start() {
        if (!config.enabled()) {
            status = CollectorStatus.STOPPED;
            message = "collector disabled";
            return;
        }
        Objects.requireNonNull(publisher, "publisher");
        if (channel != null && channel.isActive()) {
            return;
        }

        status = CollectorStatus.STARTING;
        message = "binding UDP socket on " + bindAddress + ":" + port;
        EventLoopGroup newGroup = new NioEventLoopGroup(1);
        BlockingQueue<UdpPacketWork> newQueue = new ArrayBlockingQueue<>(Math.max(1, packetQueueCapacity));
        ExecutorService newWorkerPool =
                Executors.newFixedThreadPool(
                        Math.max(1, workerThreads),
                        Thread.ofPlatform().daemon(true).name(type + "-udp-worker-", 0).factory());
        workersRunning = true;
        packetQueue = newQueue;
        workerPool = newWorkerPool;
        startWorkers(newWorkerPool, newQueue, Math.max(1, workerThreads));

        try {
            Bootstrap bootstrap = new Bootstrap();
            bootstrap.group(newGroup)
                    .channel(NioDatagramChannel.class)
                    .option(ChannelOption.SO_RCVBUF, receiveBufferBytes)
                    .handler(new DatagramHandler());

            Channel newChannel = bootstrap.bind(new InetSocketAddress(bindAddress, port)).sync().channel();
            this.group = newGroup;
            this.channel = newChannel;
            this.status = CollectorStatus.UP;
            this.message = "listening on " + bindAddress + ":" + port;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            cleanupStartupFailure(newWorkerPool, newGroup);
            status = CollectorStatus.DOWN;
            message = "interrupted while binding UDP socket";
            throw new IllegalStateException(message, e);
        } catch (RuntimeException e) {
            cleanupStartupFailure(newWorkerPool, newGroup);
            status = CollectorStatus.DOWN;
            message = "failed to bind UDP socket: " + e.getMessage();
            throw e;
        }
    }

    @Override
    public synchronized void stop() {
        Channel currentChannel = channel;
        EventLoopGroup currentGroup = group;
        ExecutorService currentWorkerPool = workerPool;
        channel = null;
        group = null;
        workerPool = null;
        workersRunning = false;
        packetQueue = null;

        if (currentChannel != null) {
            currentChannel.close().awaitUninterruptibly();
        }
        if (currentGroup != null) {
            shutdownGroup(currentGroup);
        }
        if (currentWorkerPool != null) {
            shutdownWorkerPool(currentWorkerPool);
        }
        status = CollectorStatus.STOPPED;
        message = "stopped";
    }

    @Override
    public CollectorHealth health() {
        CollectorStatus currentStatus = status;
        if (currentStatus == CollectorStatus.UP
                && (decodeErrors.get() > 0 || publishErrors.get() > 0 || packetsDropped.get() > 0)) {
            currentStatus = CollectorStatus.DEGRADED;
        }
        BlockingQueue<UdpPacketWork> currentQueue = packetQueue;
        String healthMessage =
                message
                        + " packets="
                        + packetsReceived.get()
                        + " dropped_packets="
                        + packetsDropped.get()
                        + " records="
                        + recordsPublished.get()
                        + " decode_errors="
                        + decodeErrors.get()
                        + " publish_errors="
                        + publishErrors.get()
                        + " publish_backpressure_retries="
                        + publishBackpressureRetries.get()
                        + " queue_depth="
                        + (currentQueue == null ? 0 : currentQueue.size())
                        + " queue_capacity="
                        + Math.max(1, packetQueueCapacity)
                        + " workers="
                        + Math.max(1, workerThreads);
        return new CollectorHealth(currentStatus, healthMessage, Instant.now(), lastRecordAt);
    }

    protected abstract List<RawFlowRecord> decode(
            ByteBuf packet, String exporterIp, int exporterPort, Instant receivedAt);

    private void handlePacket(DatagramPacket packet) {
        packetsReceived.incrementAndGet();
        Instant receivedAt = Instant.now();
        String exporterIp = packet.sender().getAddress().getHostAddress();
        int exporterPort = packet.sender().getPort();
        ByteBuf content = packet.content();
        byte[] payload = new byte[content.readableBytes()];
        content.getBytes(content.readerIndex(), payload);

        BlockingQueue<UdpPacketWork> currentQueue = packetQueue;
        if (currentQueue == null
                || !currentQueue.offer(new UdpPacketWork(payload, exporterIp, exporterPort, receivedAt))) {
            packetsDropped.incrementAndGet();
            message = "dropped UDP packet from " + exporterIp + ": packet queue is full";
        }
    }

    private void processPacket(UdpPacketWork packet) {
        List<RawFlowRecord> records;
        ByteBuf payload = Unpooled.wrappedBuffer(packet.payload());
        try {
            records = decode(payload, packet.exporterIp(), packet.exporterPort(), packet.receivedAt());
        } catch (RuntimeException e) {
            decodeErrors.incrementAndGet();
            message = "failed to decode packet from " + packet.exporterIp() + ": " + e.getMessage();
            return;
        } finally {
            payload.release();
        }

        for (RawFlowRecord record : records) {
            publish(record);
        }
        if (!records.isEmpty()) {
            lastRecordAt = packet.receivedAt();
        }
    }

    private void publish(RawFlowRecord record) {
        int attempts = Math.max(1, publishBackpressureRetryAttempts);
        for (int attempt = 1; attempt <= attempts; attempt++) {
            CompletionStage<Void> completion;
            try {
                completion = publisher.publish(record);
            } catch (RuntimeException e) {
                if (retryBackpressure(e, attempt, attempts)) {
                    continue;
                }
                handlePublishError(e);
                return;
            }
            if (completion == null) {
                recordsPublished.incrementAndGet();
                return;
            }

            CompletableFuture<Void> future = completion.toCompletableFuture();
            if (future.isCompletedExceptionally()) {
                Throwable error = completionFailure(future);
                if (retryBackpressure(error, attempt, attempts)) {
                    continue;
                }
                handlePublishError(error);
                return;
            }

            completion.whenComplete(
                    (ignored, error) -> {
                        if (error == null) {
                            recordsPublished.incrementAndGet();
                        } else {
                            handlePublishError(error);
                        }
                    });
            return;
        }
    }

    private boolean retryBackpressure(Throwable error, int attempt, int attempts) {
        Throwable cause = unwrap(error);
        if (!(cause instanceof PublishBackpressureException) || attempt >= attempts) {
            return false;
        }
        publishBackpressureRetries.incrementAndGet();
        if (publishBackpressureRetryDelayMs <= 0) {
            Thread.onSpinWait();
            return true;
        }
        try {
            TimeUnit.MILLISECONDS.sleep(publishBackpressureRetryDelayMs);
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private void handlePublishError(Throwable error) {
        Throwable cause = unwrap(error);
        publishErrors.incrementAndGet();
        message = "failed to publish record: " + cause.getMessage();
    }

    private void startWorkers(ExecutorService workers, BlockingQueue<UdpPacketWork> queue, int workerCount) {
        for (int i = 0; i < workerCount; i++) {
            workers.execute(() -> workerLoop(queue));
        }
    }

    private void workerLoop(BlockingQueue<UdpPacketWork> queue) {
        while (workersRunning || !queue.isEmpty()) {
            try {
                UdpPacketWork packet = queue.poll(250, TimeUnit.MILLISECONDS);
                if (packet != null) {
                    processPacket(packet);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (RuntimeException e) {
                decodeErrors.incrementAndGet();
                message = "UDP worker error: " + e.getMessage();
            }
        }
    }

    private void cleanupStartupFailure(ExecutorService workers, EventLoopGroup eventLoopGroup) {
        workersRunning = false;
        packetQueue = null;
        workerPool = null;
        shutdownWorkerPool(workers);
        shutdownGroup(eventLoopGroup);
    }

    private static void shutdownGroup(EventLoopGroup eventLoopGroup) {
        eventLoopGroup.shutdownGracefully().awaitUninterruptibly();
    }

    private static void shutdownWorkerPool(ExecutorService workers) {
        workers.shutdown();
        try {
            if (!workers.awaitTermination(10, TimeUnit.SECONDS)) {
                workers.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            workers.shutdownNow();
        }
    }

    private static Throwable completionFailure(CompletableFuture<Void> future) {
        try {
            future.join();
            return null;
        } catch (CompletionException e) {
            return unwrap(e);
        } catch (RuntimeException e) {
            return unwrap(e);
        }
    }

    private static Throwable unwrap(Throwable error) {
        Throwable current = error;
        while (current instanceof CompletionException && current.getCause() != null) {
            current = current.getCause();
        }
        return current == null ? new IllegalStateException("unknown publish failure") : current;
    }

    private static String stringProperty(
            Map<String, Object> properties, String primaryKey, String aliasKey, String defaultValue) {
        Object value = properties.get(primaryKey);
        if (value == null) {
            value = properties.get(aliasKey);
        }
        return value == null ? defaultValue : value.toString();
    }

    private static int intProperty(Map<String, Object> properties, String key, int defaultValue) {
        Object value = properties.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Number number) {
            return number.intValue();
        }
        return Integer.parseInt(value.toString());
    }

    private static int intProperty(
            Map<String, Object> properties, String primaryKey, String aliasKey, int defaultValue) {
        Object value = properties.get(primaryKey);
        if (value == null) {
            value = properties.get(aliasKey);
        }
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Number number) {
            return number.intValue();
        }
        return Integer.parseInt(value.toString());
    }

    private static int defaultWorkerThreads() {
        return Math.min(8, Math.max(2, Runtime.getRuntime().availableProcessors()));
    }

    private final class DatagramHandler extends SimpleChannelInboundHandler<DatagramPacket> {

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, DatagramPacket packet) {
            handlePacket(packet);
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            decodeErrors.incrementAndGet();
            message = "UDP handler error: " + cause.getMessage();
        }
    }

    private record UdpPacketWork(byte[] payload, String exporterIp, int exporterPort, Instant receivedAt) {}
}
