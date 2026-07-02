package com.kien.networkflowcollector.query;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.kien.networkflowcollector.storage.AggBucket;
import java.util.Objects;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record AggregationBucketResponse(
        @JsonProperty("src_ip") String srcIp,
        @JsonProperty("dst_port") String dstPort,
        long bytes,
        long packets,
        @JsonProperty("flow_count") long flowCount) {

    public static AggregationBucketResponse topTalker(AggBucket bucket) {
        Objects.requireNonNull(bucket, "bucket");
        return new AggregationBucketResponse(
                bucket.key(), null, bucket.bytesTotal(), bucket.packetsTotal(), bucket.flows());
    }

    public static AggregationBucketResponse topPort(AggBucket bucket) {
        Objects.requireNonNull(bucket, "bucket");
        return new AggregationBucketResponse(
                null, bucket.key(), bucket.bytesTotal(), bucket.packetsTotal(), bucket.flows());
    }
}
