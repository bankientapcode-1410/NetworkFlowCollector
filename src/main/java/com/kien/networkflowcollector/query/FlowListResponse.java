package com.kien.networkflowcollector.query;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record FlowListResponse(
        List<FlowResponse> data,
        PaginationResponse pagination,
        @JsonProperty("took_ms") long tookMs) {

    public FlowListResponse {
        data = List.copyOf(data);
    }
}
