package com.kien.networkflowcollector.storage;

import java.time.Instant;
import java.util.UUID;

public record FlowCursor(Instant tsStart, UUID flowId, int limit) {}
