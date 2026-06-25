package com.kien.networkflowcollector.collectors.netflow.ipfix;

import com.kien.networkflowcollector.collectors.netflow.UdpFlowCollectorSupport;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import io.netty.buffer.ByteBuf;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.springframework.stereotype.Component;

@Component
public class IpfixCollector extends UdpFlowCollectorSupport {

    private static final int DEFAULT_PORT = 4739;

    private final IpfixDecoder decoder = new IpfixDecoder();

    public IpfixCollector() {
        super("ipfix", Set.of(IpfixProtocol.SOURCE_TYPE), DEFAULT_PORT);
    }

    @Override
    protected List<RawFlowRecord> decode(
            ByteBuf packet, String exporterIp, int exporterPort, Instant receivedAt) {
        return decoder.decode(packet, exporterIp, exporterPort, receivedAt);
    }
}
