package com.kien.networkflowcollector.storage;

public record AggBucket(String key, long flows, long bytesTotal, long packetsTotal) {}
