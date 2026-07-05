package com.kien.networkflowcollector.plugins.rest;

import java.time.Instant;

record RestIngestReceipt(String batchId, int acceptedRecords, Instant acceptedAt) {}
