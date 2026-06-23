package com.kien.networkflowcollector.storage;

import java.util.List;
import java.util.Optional;

public record FlowSlice<T>(List<T> records, Optional<FlowCursor> nextCursor, boolean hasMore) {

    public FlowSlice {
        records = List.copyOf(records);
        nextCursor = nextCursor == null ? Optional.empty() : nextCursor;
    }
}
