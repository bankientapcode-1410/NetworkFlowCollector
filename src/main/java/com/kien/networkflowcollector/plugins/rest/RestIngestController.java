package com.kien.networkflowcollector.plugins.rest;

import com.fasterxml.jackson.databind.JsonNode;
import com.kien.networkflowcollector.collector.CollectorRegistry;
import com.kien.networkflowcollector.spi.FlowCollector;
import java.time.Instant;
import java.util.Objects;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = RestProtocol.ENDPOINT, produces = MediaType.APPLICATION_JSON_VALUE)
public class RestIngestController {

    private final CollectorRegistry collectorRegistry;

    public RestIngestController(CollectorRegistry collectorRegistry) {
        this.collectorRegistry = Objects.requireNonNull(collectorRegistry, "collectorRegistry");
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<RestIngestResponse> ingest(@RequestBody JsonNode payload) {
        RestIngestReceipt receipt = restCollector().ingest(payload);
        return ResponseEntity.accepted()
                .body(new RestIngestResponse(receipt.batchId(), receipt.acceptedRecords(), receipt.acceptedAt()));
    }

    @ExceptionHandler(RestIngestValidationException.class)
    ResponseEntity<RestIngestErrorResponse> validationError(RestIngestValidationException e) {
        return error(HttpStatus.UNPROCESSABLE_ENTITY, "validation_failed", e.getMessage());
    }

    @ExceptionHandler(RestIngestBackpressureException.class)
    ResponseEntity<RestIngestErrorResponse> backpressure(RestIngestBackpressureException e) {
        return error(HttpStatus.TOO_MANY_REQUESTS, "backpressure", e.getMessage());
    }

    @ExceptionHandler({RestIngestUnavailableException.class, RestIngestPublishException.class})
    ResponseEntity<RestIngestErrorResponse> unavailable(RuntimeException e) {
        return error(HttpStatus.SERVICE_UNAVAILABLE, "unavailable", e.getMessage());
    }

    private RestFlowCollector restCollector() {
        for (FlowCollector collector : collectorRegistry.collectors()) {
            if (collector instanceof RestFlowCollector restFlowCollector) {
                return restFlowCollector;
            }
        }
        throw new RestIngestUnavailableException("REST ingest collector is not registered");
    }

    private static ResponseEntity<RestIngestErrorResponse> error(
            HttpStatus status, String error, String message) {
        return ResponseEntity.status(status).body(new RestIngestErrorResponse(error, message, Instant.now()));
    }

    public record RestIngestResponse(String batchId, int acceptedRecords, Instant acceptedAt) {}

    public record RestIngestErrorResponse(String error, String message, Instant timestamp) {}
}
