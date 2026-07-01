package com.kien.networkflowcollector.kafka;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.util.Objects;

public class RawFlowRecordJsonCodec {

    private final ObjectMapper objectMapper;

    public RawFlowRecordJsonCodec(ObjectMapper objectMapper) {
        this.objectMapper =
                Objects.requireNonNull(objectMapper, "objectMapper")
                        .copy()
                        .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
                        .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                        .enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);
    }

    public String encode(RawFlowRecord record) {
        try {
            return objectMapper.writeValueAsString(Objects.requireNonNull(record, "record"));
        } catch (JsonProcessingException e) {
            throw new RawFlowRecordCodecException("Failed to serialize raw flow record", e);
        }
    }

    public RawFlowRecord decode(String json) {
        try {
            return objectMapper.readValue(Objects.requireNonNull(json, "json"), RawFlowRecord.class);
        } catch (JsonProcessingException e) {
            throw new RawFlowRecordCodecException("Failed to deserialize raw flow record", e);
        }
    }

    public String encodeDeadLetter(DeadLetterFlowRecord record) {
        try {
            return objectMapper.writeValueAsString(Objects.requireNonNull(record, "record"));
        } catch (JsonProcessingException e) {
            throw new RawFlowRecordCodecException("Failed to serialize dead-letter flow record", e);
        }
    }
}
