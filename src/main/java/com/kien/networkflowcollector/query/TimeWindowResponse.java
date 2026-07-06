package com.kien.networkflowcollector.query;

import com.fasterxml.jackson.annotation.JsonFormat;
import java.time.Instant;

public record TimeWindowResponse(
        @JsonFormat(shape = JsonFormat.Shape.STRING) Instant from,
        @JsonFormat(shape = JsonFormat.Shape.STRING) Instant to) {}
