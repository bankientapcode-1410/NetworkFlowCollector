package com.kien.networkflowcollector.plugins.netflow.v5;

import com.kien.networkflowcollector.plugins.netflow.NetFlowProtocolSupport;
import java.time.Instant;

final class NetFlowV5Protocol {

    static final String SOURCE_TYPE = "netflow-v5";
    static final int VERSION = 5;
    static final int HEADER_LENGTH = 24;
    static final int RECORD_LENGTH = 48;
    static final int MAX_RECORDS = 30;

    private NetFlowV5Protocol() {}

    static String ipv4(long value) {
        return NetFlowProtocolSupport.ipv4(value);
    }

    static Instant exportTime(long unixSeconds, long unixNanos) {
        return NetFlowProtocolSupport.exportTime(unixSeconds, unixNanos);
    }

    static Instant switchedTime(Instant exportTime, long sysUptimeMillis, long switchedMillis) {
        return NetFlowProtocolSupport.switchedTime(exportTime, sysUptimeMillis, switchedMillis);
    }

    static long durationMillis(long firstSwitchedMillis, long lastSwitchedMillis) {
        return NetFlowProtocolSupport.durationMillis(firstSwitchedMillis, lastSwitchedMillis);
    }

    static String protocolName(int protocolNumber) {
        return NetFlowProtocolSupport.protocolName(protocolNumber);
    }
}
