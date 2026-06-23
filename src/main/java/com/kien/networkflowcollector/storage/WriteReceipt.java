package com.kien.networkflowcollector.storage;

import java.time.Instant;

public record WriteReceipt(int recordsWritten, Instant committedAt) {}
