package com.kien.networkflowcollector.collectors.zeek;

import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

@Component
public class ZeekCollector extends ZeekFileCollectorSupport {

    private final Map<Path, ZeekConnLogDecoder> decoders = new ConcurrentHashMap<>();

    public ZeekCollector() {
        super(ZeekProtocol.COLLECTOR_TYPE, Set.of(ZeekProtocol.CONN_SOURCE_TYPE));
    }

    @Override
    protected Optional<RawFlowRecord> decodeLine(
            Path path, String line, String exporterIp, Instant receivedAt) {
        return decoders
                .computeIfAbsent(path, ignored -> new ZeekConnLogDecoder())
                .decodeLine(line, exporterIp, receivedAt);
    }
}
