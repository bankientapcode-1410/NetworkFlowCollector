package com.kien.networkflowcollector.query;

import java.util.UUID;

public class FlowNotFoundException extends RuntimeException {

    private final UUID flowId;

    public FlowNotFoundException(UUID flowId) {
        super("flow not found: " + flowId);
        this.flowId = flowId;
    }

    public UUID flowId() {
        return flowId;
    }
}
