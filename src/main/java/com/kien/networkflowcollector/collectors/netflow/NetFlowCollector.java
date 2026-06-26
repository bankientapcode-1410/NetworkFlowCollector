package com.kien.networkflowcollector.collectors.netflow;

import com.kien.networkflowcollector.collectors.netflow.v5.NetFlowV5Decoder;
import com.kien.networkflowcollector.collectors.netflow.v9.NetFlowV9Decoder;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import io.netty.buffer.ByteBuf;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.springframework.stereotype.Component;

@Component
public class NetFlowCollector extends UdpFlowCollectorSupport {

    private static final int DEFAULT_PORT = 2055;
    private static final int NETFLOW_V5_VERSION = 5;
    private static final int NETFLOW_V9_VERSION = 9;

    private final NetFlowV5Decoder v5Decoder = new NetFlowV5Decoder();
    private final NetFlowV9Decoder v9Decoder = new NetFlowV9Decoder();

    public NetFlowCollector() {
        super("netflow", Set.of("netflow-v5", "netflow-v9"), DEFAULT_PORT);
    }

    @Override
    protected List<RawFlowRecord> decode(
            ByteBuf packet, String exporterIp, int exporterPort, Instant receivedAt) {
        if (packet.readableBytes() < Short.BYTES) {
            throw new IllegalArgumentException(
                    "NetFlow packet too short: " + packet.readableBytes() + " bytes");
        }

        int version = packet.getUnsignedShort(packet.readerIndex());
        return switch (version) {
            case NETFLOW_V5_VERSION -> v5Decoder.decode(packet, exporterIp, receivedAt);
            case NETFLOW_V9_VERSION -> v9Decoder.decode(packet, exporterIp, exporterPort, receivedAt);
            default -> throw new IllegalArgumentException("Unsupported NetFlow version: " + version);
        };
    }
}
