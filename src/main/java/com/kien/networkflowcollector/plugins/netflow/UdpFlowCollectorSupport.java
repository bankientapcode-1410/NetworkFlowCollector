package com.kien.networkflowcollector.plugins.netflow;

import com.kien.networkflowcollector.spi.CollectorConfig;
import com.kien.networkflowcollector.spi.CollectorHealth;
import com.kien.networkflowcollector.spi.CollectorStatus;
import com.kien.networkflowcollector.spi.FlowCollector;
import com.kien.networkflowcollector.spi.FlowPublisher;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
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
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicLong;

public abstract class UdpFlowCollectorSupport implements FlowCollector {

    private static final String DEFAULT_BIND_ADDRESS = "0.0.0.0";
    private static final int DEFAULT_RECEIVE_BUFFER_BYTES = 1_048_576;

    private final String type;
    private final Set<String> supportedSourceTypes;
    private final int defaultPort;
    private final AtomicLong packetsReceived = new AtomicLong();
    private final AtomicLong recordsPublished = new AtomicLong();
    private final AtomicLong decodeErrors = new AtomicLong();
    private final AtomicLong publishErrors = new AtomicLong();

    private volatile CollectorConfig config = new CollectorConfig(false, Map.of());
    private volatile FlowPublisher publisher;
    private volatile EventLoopGroup group;
    private volatile Channel channel;
    private volatile CollectorStatus status = CollectorStatus.STOPPED;
    private volatile String message = "not initialized";
    private volatile Instant lastRecordAt;
    private volatile String bindAddress = DEFAULT_BIND_ADDRESS;
    private volatile int port;
    private volatile int receiveBufferBytes = DEFAULT_RECEIVE_BUFFER_BYTES;

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
            shutdownGroup(newGroup);
            status = CollectorStatus.DOWN;
            message = "interrupted while binding UDP socket";
            throw new IllegalStateException(message, e);
        } catch (RuntimeException e) {
            shutdownGroup(newGroup);
            status = CollectorStatus.DOWN;
            message = "failed to bind UDP socket: " + e.getMessage();
            throw e;
        }
    }

    @Override
    public synchronized void stop() {
        Channel currentChannel = channel;
        EventLoopGroup currentGroup = group;
        channel = null;
        group = null;

        if (currentChannel != null) {
            currentChannel.close().awaitUninterruptibly();
        }
        if (currentGroup != null) {
            shutdownGroup(currentGroup);
        }
        status = CollectorStatus.STOPPED;
        message = "stopped";
    }

    @Override
    public CollectorHealth health() {
        CollectorStatus currentStatus = status;
        if (currentStatus == CollectorStatus.UP
                && (decodeErrors.get() > 0 || publishErrors.get() > 0)) {
            currentStatus = CollectorStatus.DEGRADED;
        }
        String healthMessage =
                message
                        + " packets="
                        + packetsReceived.get()
                        + " records="
                        + recordsPublished.get()
                        + " decode_errors="
                        + decodeErrors.get()
                        + " publish_errors="
                        + publishErrors.get();
        return new CollectorHealth(currentStatus, healthMessage, Instant.now(), lastRecordAt);
    }

    protected abstract List<RawFlowRecord> decode(
            ByteBuf packet, String exporterIp, int exporterPort, Instant receivedAt);

    private void handlePacket(DatagramPacket packet) {
        packetsReceived.incrementAndGet();
        Instant receivedAt = Instant.now();
        String exporterIp = packet.sender().getAddress().getHostAddress();
        List<RawFlowRecord> records;
        try {
            records = decode(packet.content(), exporterIp, packet.sender().getPort(), receivedAt);
        } catch (RuntimeException e) {
            decodeErrors.incrementAndGet();
            message = "failed to decode packet from " + exporterIp + ": " + e.getMessage();
            return;
        }

        for (RawFlowRecord record : records) {
            publish(record);
        }
        if (!records.isEmpty()) {
            lastRecordAt = receivedAt;
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
                            message = "failed to publish record: " + error.getMessage();
                        }
                    });
        } catch (RuntimeException e) {
            publishErrors.incrementAndGet();
            message = "failed to publish record: " + e.getMessage();
        }
    }

    private static void shutdownGroup(EventLoopGroup eventLoopGroup) {
        eventLoopGroup.shutdownGracefully().awaitUninterruptibly();
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
}
