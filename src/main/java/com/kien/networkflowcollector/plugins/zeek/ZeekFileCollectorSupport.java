package com.kien.networkflowcollector.plugins.zeek;

import com.kien.networkflowcollector.plugins.TextLogFlowCollectorSupport;
import java.util.Set;

public abstract class ZeekFileCollectorSupport extends TextLogFlowCollectorSupport {

    protected ZeekFileCollectorSupport(String type, Set<String> supportedSourceTypes) {
        super(type, supportedSourceTypes, ZeekProtocol.DEFAULT_EXPORTER_IP, "Zeek");
    }
}
