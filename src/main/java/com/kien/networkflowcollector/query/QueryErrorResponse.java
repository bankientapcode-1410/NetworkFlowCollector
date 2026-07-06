package com.kien.networkflowcollector.query;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;

public record QueryErrorResponse(QueryError error) {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record QueryError(
            String code,
            String message,
            @JsonProperty("trace_id") String traceId,
            @JsonFormat(shape = JsonFormat.Shape.STRING)
            Instant timestamp) {}
}
