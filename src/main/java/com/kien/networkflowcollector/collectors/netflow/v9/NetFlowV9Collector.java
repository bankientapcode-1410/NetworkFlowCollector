package com.kien.networkflowcollector.collectors.netflow.v9;

import com.kien.networkflowcollector.collectors.netflow.UdpFlowCollectorSupport;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import io.netty.buffer.ByteBuf;
import java.time.Instant;
import java.util.List;
import java.util.Set;

public class NetFlowV9Collector extends UdpFlowCollectorSupport {

    private static final int DEFAULT_PORT = 2055;

    private final NetFlowV9Decoder decoder = new NetFlowV9Decoder();

    public NetFlowV9Collector() {
        super("netflow-v9", Set.of(NetFlowV9Protocol.SOURCE_TYPE), DEFAULT_PORT);
    }

    @Override
    protected List<RawFlowRecord> decode(
            ByteBuf packet, String exporterIp, int exporterPort, Instant receivedAt) {
        return decoder.decode(packet, exporterIp, exporterPort, receivedAt);
    }
}
