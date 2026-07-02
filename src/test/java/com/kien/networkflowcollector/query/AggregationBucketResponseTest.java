package com.kien.networkflowcollector.query;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kien.networkflowcollector.storage.AggBucket;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("AggregationBucketResponse")
class AggregationBucketResponseTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    @DisplayName("topTalker maps AggBucket flows to flow_count")
    void topTalker_mapsFlowCountJsonField() throws Exception {
        AggregationBucketResponse response =
                AggregationBucketResponse.topTalker(new AggBucket("10.20.30.40", 12L, 900L, 40L));

        String json = objectMapper.writeValueAsString(response);

        assertThat(json).contains("\"src_ip\":\"10.20.30.40\"");
        assertThat(json).contains("\"bytes\":900");
        assertThat(json).contains("\"packets\":40");
        assertThat(json).contains("\"flow_count\":12");
        assertThat(json).doesNotContain("flows");
        assertThat(json).doesNotContain("flowCount");
        assertThat(json).doesNotContain("dst_port");
    }

    @Test
    @DisplayName("topPort uses destination port as the response key")
    void topPort_mapsDestinationPortJsonField() throws Exception {
        AggregationBucketResponse response =
                AggregationBucketResponse.topPort(new AggBucket("443", 20L, 1200L, 80L));

        String json = objectMapper.writeValueAsString(response);

        assertThat(json).contains("\"dst_port\":\"443\"");
        assertThat(json).contains("\"flow_count\":20");
        assertThat(json).doesNotContain("src_ip");
    }
}
