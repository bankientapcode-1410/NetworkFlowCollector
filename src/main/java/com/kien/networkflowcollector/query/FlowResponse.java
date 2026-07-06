package com.kien.networkflowcollector.query;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.kien.networkflowcollector.common.NormalizedFlow;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record FlowResponse(
        @JsonProperty("flow_id") UUID flowId,
        @JsonFormat(shape = JsonFormat.Shape.STRING)
        @JsonProperty("ts_start") Instant tsStart,
        @JsonFormat(shape = JsonFormat.Shape.STRING)
        @JsonProperty("ts_end") Instant tsEnd,
        @JsonProperty("duration_ms") long durationMs,
        @JsonProperty("src_ip") String srcIp,
        @JsonProperty("src_port") int srcPort,
        @JsonProperty("dst_ip") String dstIp,
        @JsonProperty("dst_port") int dstPort,
        String protocol,
        @JsonProperty("bytes_total") long bytesTotal,
        @JsonProperty("packets_total") long packetsTotal,
        @JsonProperty("tcp_flags") Integer tcpFlags,
        boolean sampled,
        @JsonProperty("sampling_rate") Long samplingRate,
        @JsonProperty("sample_pool") Long samplePool,
        @JsonProperty("source_type") String sourceType,
        @JsonProperty("exporter_ip") String exporterIp,
        @JsonProperty("src_country_code") String srcCountryCode,
        @JsonProperty("src_asn") Long srcAsn,
        @JsonProperty("src_as_org") String srcAsOrg,
        @JsonProperty("dst_country_code") String dstCountryCode,
        @JsonProperty("dst_asn") Long dstAsn,
        @JsonProperty("dst_as_org") String dstAsOrg,
        @JsonFormat(shape = JsonFormat.Shape.STRING)
        @JsonProperty("ingest_time") Instant ingestTime) {

    public static FlowResponse from(NormalizedFlow flow) {
        Objects.requireNonNull(flow, "flow");
        return new FlowResponse(
                flow.flowId(),
                flow.tsStart(),
                flow.tsEnd(),
                flow.durationMs(),
                flow.srcIp(),
                flow.srcPort(),
                flow.dstIp(),
                flow.dstPort(),
                flow.protocol(),
                flow.bytesTotal(),
                flow.packetsTotal(),
                flow.tcpFlags(),
                flow.sampled(),
                flow.samplingRate(),
                flow.samplePool(),
                flow.sourceType(),
                flow.exporterIp(),
                flow.srcCountryCode(),
                flow.srcAsn(),
                flow.srcAsOrg(),
                flow.dstCountryCode(),
                flow.dstAsn(),
                flow.dstAsOrg(),
                flow.ingestTime());
    }
}
