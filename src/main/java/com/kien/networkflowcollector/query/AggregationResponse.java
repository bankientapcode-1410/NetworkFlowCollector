package com.kien.networkflowcollector.query;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record AggregationResponse(
        String metric,
        String consistency,
        TimeWindowResponse window,
        List<AggregationBucketResponse> results,
        @JsonProperty("took_ms") long tookMs) {

    public AggregationResponse {
        results = List.copyOf(results);
    }
}
