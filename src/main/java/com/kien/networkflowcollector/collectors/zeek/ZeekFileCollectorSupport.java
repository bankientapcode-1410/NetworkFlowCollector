package com.kien.networkflowcollector.collectors.zeek;

import com.kien.networkflowcollector.collectors.TextLogFlowCollectorSupport;
import java.util.Set;

public abstract class ZeekFileCollectorSupport extends TextLogFlowCollectorSupport {

    protected ZeekFileCollectorSupport(String type, Set<String> supportedSourceTypes) {
        super(type, supportedSourceTypes, ZeekProtocol.DEFAULT_EXPORTER_IP, "Zeek");
    }
}
