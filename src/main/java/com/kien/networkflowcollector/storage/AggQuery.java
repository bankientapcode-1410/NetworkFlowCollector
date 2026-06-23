package com.kien.networkflowcollector.storage;

import java.time.Instant;

public record AggQuery(Instant from, Instant to, int limit) {}
