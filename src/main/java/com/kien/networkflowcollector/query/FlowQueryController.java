package com.kien.networkflowcollector.query;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.storage.AggBucket;
import com.kien.networkflowcollector.storage.FlowCursor;
import com.kien.networkflowcollector.storage.FlowQuery;
import com.kien.networkflowcollector.storage.FlowSlice;
import com.kien.networkflowcollector.storage.FlowStore;
import com.kien.networkflowcollector.storage.RetryableStorageException;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/flows", produces = MediaType.APPLICATION_JSON_VALUE)
public class FlowQueryController {

    private static final String EXACT_CONSISTENCY = "exact";

    private final FlowStore flowStore;
    private final FlowQueryBuilder queryBuilder;
    private final CursorHandler cursorHandler;

    public FlowQueryController(
            FlowStore flowStore, FlowQueryBuilder queryBuilder, CursorHandler cursorHandler) {
        this.flowStore = Objects.requireNonNull(flowStore, "flowStore");
        this.queryBuilder = Objects.requireNonNull(queryBuilder, "queryBuilder");
        this.cursorHandler = Objects.requireNonNull(cursorHandler, "cursorHandler");
    }

    @GetMapping
    public FlowListResponse flows(
            @RequestParam(name = "start_time", required = false) String startTime,
            @RequestParam(name = "end_time", required = false) String endTime,
            @RequestParam(name = "src_ip", required = false) String srcIp,
            @RequestParam(name = "src_port", required = false) String srcPort,
            @RequestParam(name = "dst_ip", required = false) String dstIp,
            @RequestParam(name = "dst_port", required = false) String dstPort,
            @RequestParam(name = "protocol", required = false) String protocol,
            @RequestParam(name = "source_type", required = false) String sourceType,
            @RequestParam(name = "cursor", required = false) String cursorToken,
            @RequestParam(name = "limit", required = false) String limit,
            @RequestParam(name = "sort", required = false) String sort) {
        long started = System.nanoTime();
        FlowQueryBuilder.BuiltFlowQuery built =
                queryBuilder.flowQuery(
                        startTime,
                        endTime,
                        srcIp,
                        srcPort,
                        dstIp,
                        dstPort,
                        protocol,
                        sourceType,
                        limit,
                        sort,
                        cursorToken != null && !cursorToken.isBlank());
        FlowCursor cursor = decodeCursor(cursorToken, built.query(), built.sort());
        FlowSlice<NormalizedFlow> slice = flowStore.query(built.query(), cursor);
        String nextCursor =
                slice.nextCursor()
                        .map(value -> cursorHandler.encode(value, built.query(), built.sort()))
                        .orElse(null);
        List<FlowResponse> data = slice.records().stream().map(FlowResponse::from).toList();
        return new FlowListResponse(
                data,
                new PaginationResponse(effectiveLimit(built.query(), cursor), slice.hasMore(), nextCursor),
                tookMs(started));
    }

    @GetMapping("/{flow_id}")
    public FlowResponse flow(@PathVariable("flow_id") String flowIdText) {
        UUID flowId = queryBuilder.flowId(flowIdText);
        return flowStore.findById(flowId)
                .map(FlowResponse::from)
                .orElseThrow(() -> new FlowNotFoundException(flowId));
    }

    @GetMapping("/aggregations/top-talkers")
    public AggregationResponse topTalkers(
            @RequestParam(name = "start_time", required = false) String startTime,
            @RequestParam(name = "end_time", required = false) String endTime,
            @RequestParam(name = "metric", required = false) String metric,
            @RequestParam(name = "limit", required = false) String limit) {
        long started = System.nanoTime();
        FlowQueryBuilder.BuiltAggregationQuery built =
                queryBuilder.aggregationQuery(startTime, endTime, metric, limit);
        List<AggregationBucketResponse> results =
                flowStore.topTalkers(built.query()).stream()
                        .map(AggregationBucketResponse::topTalker)
                        .toList();
        return aggregationResponse(built, results, started);
    }

    @GetMapping("/aggregations/top-ports")
    public AggregationResponse topPorts(
            @RequestParam(name = "start_time", required = false) String startTime,
            @RequestParam(name = "end_time", required = false) String endTime,
            @RequestParam(name = "metric", required = false) String metric,
            @RequestParam(name = "limit", required = false) String limit) {
        long started = System.nanoTime();
        FlowQueryBuilder.BuiltAggregationQuery built =
                queryBuilder.aggregationQuery(startTime, endTime, metric, limit);
        List<AggregationBucketResponse> results =
                flowStore.topPorts(built.query()).stream()
                        .map(AggregationBucketResponse::topPort)
                        .toList();
        return aggregationResponse(built, results, started);
    }

    @ExceptionHandler(QueryValidationException.class)
    ResponseEntity<QueryErrorResponse> validationError(QueryValidationException e) {
        return error(HttpStatus.BAD_REQUEST, e.code(), e.getMessage());
    }

    @ExceptionHandler(FlowNotFoundException.class)
    ResponseEntity<QueryErrorResponse> notFound(FlowNotFoundException e) {
        return error(HttpStatus.NOT_FOUND, "FLOW_NOT_FOUND", "flow_id was not found");
    }

    @ExceptionHandler(IllegalArgumentException.class)
    ResponseEntity<QueryErrorResponse> illegalArgument(IllegalArgumentException e) {
        return error(HttpStatus.BAD_REQUEST, "INVALID_REQUEST", e.getMessage());
    }

    @ExceptionHandler(RetryableStorageException.class)
    ResponseEntity<QueryErrorResponse> storageUnavailable(RetryableStorageException e) {
        return error(HttpStatus.SERVICE_UNAVAILABLE, "STORAGE_UNAVAILABLE", "flow storage is unavailable");
    }

    private FlowCursor decodeCursor(String cursorToken, FlowQuery query, String sort) {
        if (cursorToken == null || cursorToken.isBlank()) {
            return null;
        }
        return cursorHandler.decode(cursorToken, query, sort);
    }

    private static int effectiveLimit(FlowQuery query, FlowCursor cursor) {
        if (query.limit() > 0) {
            return query.limit();
        }
        if (cursor != null) {
            return cursor.limit();
        }
        return FlowQueryBuilder.DEFAULT_FLOW_LIMIT;
    }

    private static AggregationResponse aggregationResponse(
            FlowQueryBuilder.BuiltAggregationQuery built,
            List<AggregationBucketResponse> results,
            long started) {
        return new AggregationResponse(
                built.metric(),
                EXACT_CONSISTENCY,
                new TimeWindowResponse(built.query().from(), built.query().to()),
                results,
                tookMs(started));
    }

    private static long tookMs(long started) {
        return Math.max(0, (System.nanoTime() - started) / 1_000_000);
    }

    private static ResponseEntity<QueryErrorResponse> error(
            HttpStatus status, String code, String message) {
        return ResponseEntity.status(status)
                .body(new QueryErrorResponse(
                        new QueryErrorResponse.QueryError(code, message, MDC.get("trace_id"), Instant.now())));
    }
}
