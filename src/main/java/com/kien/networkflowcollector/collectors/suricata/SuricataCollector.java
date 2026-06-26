package com.kien.networkflowcollector.collectors.suricata;

import com.kien.networkflowcollector.collectors.TextLogFlowCollectorSupport;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Component;

@Component
public class SuricataCollector extends TextLogFlowCollectorSupport {

    private final SuricataEveDecoder decoder = new SuricataEveDecoder();

    public SuricataCollector() {
        super(
                SuricataProtocol.COLLECTOR_TYPE,
                Set.of(SuricataProtocol.FLOW_SOURCE_TYPE),
                SuricataProtocol.DEFAULT_EXPORTER_IP,
                "Suricata");
    }

    @Override
    protected Optional<RawFlowRecord> decodeLine(
            Path path, String line, String exporterIp, Instant receivedAt) {
        return decoder.decodeLine(line, exporterIp, receivedAt);
    }
}
