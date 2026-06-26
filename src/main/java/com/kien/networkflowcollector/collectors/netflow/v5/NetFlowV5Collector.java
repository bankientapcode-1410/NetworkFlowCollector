package com.kien.networkflowcollector.collectors.netflow.v5;

import com.kien.networkflowcollector.collectors.netflow.UdpFlowCollectorSupport;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import io.netty.buffer.ByteBuf;
import java.time.Instant;
import java.util.List;
import java.util.Set;

public class NetFlowV5Collector extends UdpFlowCollectorSupport {

    private static final int DEFAULT_PORT = 2055;

    private final NetFlowV5Decoder decoder = new NetFlowV5Decoder();

    public NetFlowV5Collector() {
        super("netflow-v5", Set.of(NetFlowV5Protocol.SOURCE_TYPE), DEFAULT_PORT);
    }

    @Override
    protected List<RawFlowRecord> decode(
            ByteBuf packet, String exporterIp, int exporterPort, Instant receivedAt) {
        return decoder.decode(packet, exporterIp, receivedAt);
    }
}
