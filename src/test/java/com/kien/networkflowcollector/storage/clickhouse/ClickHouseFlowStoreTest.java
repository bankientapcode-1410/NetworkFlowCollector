package com.kien.networkflowcollector.storage.clickhouse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.storage.AggBucket;
import com.kien.networkflowcollector.storage.AggQuery;
import com.kien.networkflowcollector.storage.FlowCursor;
import com.kien.networkflowcollector.storage.FlowQuery;
import com.kien.networkflowcollector.storage.FlowSlice;
import com.kien.networkflowcollector.storage.RetryableStorageException;
import com.kien.networkflowcollector.storage.WriteReceipt;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("ClickHouseFlowStore")
class ClickHouseFlowStoreTest {

    private static final Instant FROM = Instant.parse("2026-06-19T00:00:00Z");
    private static final Instant TO = Instant.parse("2026-06-19T12:00:00Z");
    private static final Instant FIRST_TS = Instant.parse("2026-06-19T08:15:30.120Z");
    private static final Instant SECOND_TS = Instant.parse("2026-06-19T08:10:00Z");
    private static final String FROM_CLICKHOUSE = "2026-06-19 00:00:00.000";
    private static final String TO_CLICKHOUSE = "2026-06-19 12:00:00.000";
    private static final String FIRST_TS_CLICKHOUSE = "2026-06-19 08:15:30.120";
    private static final String CURSOR_TS_CLICKHOUSE = "2026-06-19 09:00:00.000";
    private static final UUID FIRST_ID = UUID.fromString("8f14e45f-ceea-467d-9b2e-3c1a2f9b7c10");
    private static final UUID SECOND_ID = UUID.fromString("8f14e45f-ceea-467d-9b2e-3c1a2f9b7c11");

    @Test
    @DisplayName("query builds FINAL keyset SQL and returns a cursor when more rows exist")
    void query_buildsKeysetSqlAndReturnsCursor() {
        RecordingJdbc jdbc = new RecordingJdbc(List.of(flowRow(FIRST_ID, FIRST_TS), flowRow(SECOND_ID, SECOND_TS)));
        ClickHouseFlowStore store = store(jdbc);
        FlowCursor cursor = new FlowCursor(Instant.parse("2026-06-19T09:00:00Z"), UUID.randomUUID(), 1);
        FlowQuery query =
                new FlowQuery(FROM, TO, "10.20.30.40", 54321, "93.184.216.34", 443, "TCP", "netflow-v5", 1);

        FlowSlice<NormalizedFlow> slice = store.query(query, cursor);

        assertThat(slice.records()).hasSize(1);
        assertThat(slice.records().getFirst().flowId()).isEqualTo(FIRST_ID);
        assertThat(slice.hasMore()).isTrue();
        assertThat(slice.nextCursor()).contains(new FlowCursor(FIRST_TS, FIRST_ID, 1));

        assertThat(jdbc.sql()).contains("FROM flows FINAL");
        assertThat(jdbc.sql()).contains("src_ip = toIPv6(?)");
        assertThat(jdbc.sql()).contains("src_port = ?");
        assertThat(jdbc.sql()).contains("dst_ip = toIPv6(?)");
        assertThat(jdbc.sql()).contains("dst_port = ?");
        assertThat(jdbc.sql()).contains("(ts_start, flow_id) < (?, ?)");
        assertThat(jdbc.sql()).contains("ORDER BY ts_start DESC, flow_id DESC LIMIT ?");
        assertThat(jdbc.parameters()).containsEntry(1, FROM_CLICKHOUSE);
        assertThat(jdbc.parameters()).containsEntry(2, TO_CLICKHOUSE);
        assertThat(jdbc.parameters()).containsEntry(3, "10.20.30.40");
        assertThat(jdbc.parameters()).containsEntry(4, 54321);
        assertThat(jdbc.parameters()).containsEntry(5, "93.184.216.34");
        assertThat(jdbc.parameters()).containsEntry(6, 443);
        assertThat(jdbc.parameters()).containsEntry(7, "tcp");
        assertThat(jdbc.parameters()).containsEntry(8, "netflow-v5");
        assertThat(jdbc.parameters()).containsEntry(9, CURSOR_TS_CLICKHOUSE);
        assertThat(jdbc.parameters()).containsEntry(11, 2);
    }

    @Test
    @DisplayName("query supports CIDR predicates without interpolating user input")
    void query_supportsCidrPredicate() {
        RecordingJdbc jdbc = new RecordingJdbc(List.of());
        ClickHouseFlowStore store = store(jdbc);
        FlowQuery query = new FlowQuery(FROM, TO, "10.20.0.0/16", null, null, null, null, null, 50);

        FlowSlice<NormalizedFlow> slice = store.query(query, null);

        assertThat(slice.records()).isEmpty();
        assertThat(slice.hasMore()).isFalse();
        assertThat(jdbc.sql()).contains("isIPAddressInRange(toString(src_ip), ?)");
        assertThat(jdbc.parameters()).containsEntry(3, "10.20.0.0/16");
    }

    @Test
    @DisplayName("query rejects invalid IP filters before opening JDBC")
    void query_rejectsInvalidIpFilter() {
        RecordingJdbc jdbc = new RecordingJdbc(List.of());
        ClickHouseFlowStore store = store(jdbc);
        FlowQuery query = new FlowQuery(FROM, TO, "not-an-ip", null, null, null, null, null, 50);

        assertThatThrownBy(() -> store.query(query, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("src_ip must be an IP literal");
        assertThat(jdbc.prepareCount()).isZero();
    }

    @Test
    @DisplayName("query rejects invalid CIDR filters before opening JDBC")
    void query_rejectsInvalidCidrFilter() {
        RecordingJdbc jdbc = new RecordingJdbc(List.of());
        ClickHouseFlowStore store = store(jdbc);
        FlowQuery query = new FlowQuery(FROM, TO, "10.20.0.0/99", null, null, null, null, null, 50);

        assertThatThrownBy(() -> store.query(query, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("src_ip must be an IP literal or CIDR range");
        assertThat(jdbc.prepareCount()).isZero();
    }

    @Test
    @DisplayName("batchInsert binds ClickHouse timestamp strings and explicit IPv6 conversions")
    void batchInsert_bindsClickHouseTimestampAndIpValues() {
        RecordingJdbc jdbc = new RecordingJdbc(List.of());
        ClickHouseFlowStore store = store(jdbc);

        WriteReceipt receipt = store.batchInsert(List.of(flow(FIRST_ID, FIRST_TS)));

        assertThat(receipt.recordsWritten()).isEqualTo(1);
        assertThat(jdbc.sql()).contains("toIPv6(?)");
        assertThat(jdbc.parameters()).containsEntry(2, FIRST_TS_CLICKHOUSE);
        assertThat(jdbc.parameters()).containsEntry(3, "2026-06-19 08:15:34.120");
        assertThat(jdbc.parameters()).containsEntry(5, "10.20.30.40");
        assertThat(jdbc.parameters()).containsEntry(17, "10.0.0.1");
        assertThat(jdbc.parameters()).containsEntry(24, "2026-06-19 08:15:35.120");
    }

    @Test
    @DisplayName("batchInsert treats explicit JDBC row failures as retryable")
    void batchInsert_rejectsFailedBatchResult() {
        RecordingJdbc jdbc = new RecordingJdbc(List.of()).withBatchResult(Statement.EXECUTE_FAILED);
        ClickHouseFlowStore store = store(jdbc);

        assertThatThrownBy(() -> store.batchInsert(List.of(flow(FIRST_ID, FIRST_TS))))
                .isInstanceOf(RetryableStorageException.class)
                .hasMessageContaining("ClickHouse batch insert failed");
    }

    @Test
    @DisplayName("truncate clears the flows table for clean demo startup")
    void truncate_executesTruncateStatement() {
        RecordingJdbc jdbc = new RecordingJdbc(List.of());
        ClickHouseFlowStore store = store(jdbc);

        store.truncate();

        assertThat(jdbc.executedSql()).isEqualTo("TRUNCATE TABLE IF EXISTS flows");
    }

    @Test
    @DisplayName("findById reads flows FINAL and maps a normalized flow")
    void findById_mapsFlow() {
        RecordingJdbc jdbc = new RecordingJdbc(List.of(flowRow(FIRST_ID, FIRST_TS)));
        ClickHouseFlowStore store = store(jdbc);

        Optional<NormalizedFlow> result = store.findById(FIRST_ID);

        assertThat(result).isPresent();
        assertThat(result.orElseThrow().srcIp()).isEqualTo("10.20.30.40");
        assertThat(result.orElseThrow().tcpFlags()).isEqualTo(27);
        assertThat(result.orElseThrow().srcAsn()).isEqualTo(64512L);
        assertThat(jdbc.sql()).contains("FROM flows FINAL WHERE flow_id = ?");
        assertThat(jdbc.parameters()).containsEntry(1, FIRST_ID);
    }

    @Test
    @DisplayName("findById maps driver-returned InetAddress IP objects")
    void findById_mapsInetAddressIpObjects() throws Exception {
        Map<String, Object> row = flowRow(FIRST_ID, FIRST_TS);
        row.put("src_ip", InetAddress.getByName("10.20.30.40"));
        row.put("dst_ip", InetAddress.getByName("93.184.216.34"));
        row.put("exporter_ip", InetAddress.getByName("10.0.0.1"));
        RecordingJdbc jdbc = new RecordingJdbc(List.of(row));
        ClickHouseFlowStore store = store(jdbc);

        NormalizedFlow result = store.findById(FIRST_ID).orElseThrow();

        assertThat(result.srcIp()).isEqualTo("10.20.30.40");
        assertThat(result.dstIp()).isEqualTo("93.184.216.34");
        assertThat(result.exporterIp()).isEqualTo("10.0.0.1");
    }

    @Test
    @DisplayName("topTalkers orders by the allow-listed aggregation metric")
    void topTalkers_ordersByMetric() {
        RecordingJdbc jdbc = new RecordingJdbc(List.of(aggRow("10.20.30.40", 12L, 900L, 40L)));
        ClickHouseFlowStore store = store(jdbc);

        List<AggBucket> buckets = store.topTalkers(new AggQuery(FROM, TO, 5, AggQuery.Metric.PACKETS));

        assertThat(buckets).containsExactly(new AggBucket("10.20.30.40", 12L, 900L, 40L));
        assertThat(jdbc.sql()).contains("toString(src_ip) AS bucket_key");
        assertThat(jdbc.sql()).contains("ORDER BY packets_total DESC, bucket_key ASC");
        assertThat(jdbc.parameters()).containsEntry(1, FROM_CLICKHOUSE);
        assertThat(jdbc.parameters()).containsEntry(2, TO_CLICKHOUSE);
        assertThat(jdbc.parameters()).containsEntry(3, 5);
    }

    @Test
    @DisplayName("topPorts groups by destination port")
    void topPorts_groupsByDestinationPort() {
        RecordingJdbc jdbc = new RecordingJdbc(List.of(aggRow("443", 20L, 1200L, 80L)));
        ClickHouseFlowStore store = store(jdbc);

        List<AggBucket> buckets = store.topPorts(new AggQuery(FROM, TO, 3, AggQuery.Metric.FLOWS));

        assertThat(buckets).containsExactly(new AggBucket("443", 20L, 1200L, 80L));
        assertThat(jdbc.sql()).contains("toString(dst_port) AS bucket_key");
        assertThat(jdbc.sql()).contains("ORDER BY flow_count DESC, bucket_key ASC");
    }

    @Test
    @DisplayName("query rejects invalid time ranges before opening JDBC")
    void query_rejectsInvalidTimeRange() {
        RecordingJdbc jdbc = new RecordingJdbc(List.of());
        ClickHouseFlowStore store = store(jdbc);
        FlowQuery query = new FlowQuery(TO, FROM, null, null, null, null, null, null, 50);

        assertThatThrownBy(() -> store.query(query, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("from must be before to");
        assertThat(jdbc.prepareCount()).isZero();
    }

    @Test
    @DisplayName("query rejects limits above the SDD maximum")
    void query_rejectsTooLargeLimit() {
        RecordingJdbc jdbc = new RecordingJdbc(List.of());
        ClickHouseFlowStore store = store(jdbc);
        FlowQuery query = new FlowQuery(FROM, TO, null, null, null, null, null, null, 1001);

        assertThatThrownBy(() -> store.query(query, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("query limit must be <= 1000");
    }

    private static ClickHouseFlowStore store(RecordingJdbc jdbc) {
        return new ClickHouseFlowStore(new ClickHouseProperties(), jdbc);
    }

    private static NormalizedFlow flow(UUID flowId, Instant tsStart) {
        return new NormalizedFlow(
                flowId,
                tsStart,
                tsStart.plusSeconds(4),
                4000L,
                "10.20.30.40",
                54321,
                "93.184.216.34",
                443,
                "tcp",
                18432L,
                24L,
                27,
                false,
                null,
                null,
                "netflow-v5",
                "10.0.0.1",
                "VN",
                64512L,
                "Example Source",
                "US",
                15133L,
                "Example Network",
                tsStart.plusSeconds(5));
    }

    private static Map<String, Object> flowRow(UUID flowId, Instant tsStart) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("flow_id", flowId);
        row.put("ts_start", tsStart);
        row.put("ts_end", tsStart.plusSeconds(4));
        row.put("duration_ms", 4000L);
        row.put("src_ip", "10.20.30.40");
        row.put("src_port", 54321);
        row.put("dst_ip", "93.184.216.34");
        row.put("dst_port", 443);
        row.put("protocol", "tcp");
        row.put("bytes_total", 18432L);
        row.put("packets_total", 24L);
        row.put("tcp_flags", 27);
        row.put("sampled", false);
        row.put("sampling_rate", null);
        row.put("sample_pool", null);
        row.put("source_type", "netflow-v5");
        row.put("exporter_ip", "10.0.0.1");
        row.put("src_country_code", "VN");
        row.put("src_asn", 64512L);
        row.put("src_as_org", "Example Source");
        row.put("dst_country_code", "US");
        row.put("dst_asn", 15133L);
        row.put("dst_as_org", "Example Network");
        row.put("ingest_time", tsStart.plusSeconds(5));
        return row;
    }

    private static Map<String, Object> aggRow(String key, long flows, long bytes, long packets) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("bucket_key", key);
        row.put("flow_count", flows);
        row.put("bytes_total", bytes);
        row.put("packets_total", packets);
        return row;
    }

    private static final class RecordingJdbc implements ClickHouseFlowStore.ConnectionProvider {
        private final List<Map<String, Object>> rows;
        private final Map<Integer, Object> parameters = new LinkedHashMap<>();
        private int[] batchResult = new int[0];
        private String sql;
        private String executedSql;
        private int prepareCount;

        private RecordingJdbc(List<Map<String, Object>> rows) {
            this.rows = rows;
        }

        private RecordingJdbc withBatchResult(int... batchResult) {
            this.batchResult = batchResult;
            return this;
        }

        @Override
        public Connection getConnection() {
            return proxy(Connection.class, this::connectionInvocation);
        }

        private Object connectionInvocation(Object proxy, Method method, Object[] args) {
            return switch (method.getName()) {
                case "prepareStatement" -> {
                    sql = (String) args[0];
                    prepareCount++;
                    yield proxy(PreparedStatement.class, this::statementInvocation);
                }
                case "createStatement" -> proxy(Statement.class, this::statementInvocation);
                case "close" -> null;
                case "isClosed" -> false;
                default -> defaultValue(method.getReturnType());
            };
        }

        private Object statementInvocation(Object proxy, Method method, Object[] args) {
            String name = method.getName();
            if (name.startsWith("set") && args != null && args.length > 0 && args[0] instanceof Integer index) {
                parameters.put(index, "setNull".equals(name) ? null : args[1]);
                return null;
            }
            return switch (name) {
                case "execute" -> {
                    executedSql = (String) args[0];
                    yield true;
                }
                case "executeQuery" -> resultSet();
                case "executeBatch" -> batchResult;
                case "addBatch", "close" -> null;
                default -> defaultValue(method.getReturnType());
            };
        }

        private ResultSet resultSet() {
            ResultSetInvocation invocation = new ResultSetInvocation(rows);
            return proxy(ResultSet.class, invocation::invoke);
        }

        private String sql() {
            return sql;
        }

        private String executedSql() {
            return executedSql;
        }

        private Map<Integer, Object> parameters() {
            return parameters;
        }

        private int prepareCount() {
            return prepareCount;
        }
    }

    private static final class ResultSetInvocation {
        private final List<Map<String, Object>> rows;
        private int cursor = -1;
        private boolean lastWasNull;

        private ResultSetInvocation(List<Map<String, Object>> rows) {
            this.rows = rows;
        }

        private Object invoke(Object proxy, Method method, Object[] args) {
            String name = method.getName();
            return switch (name) {
                case "next" -> ++cursor < rows.size();
                case "getObject" -> value(args[0].toString());
                case "getString" -> stringValue(args[0].toString());
                case "getInt" -> intValue(args[0].toString());
                case "getLong" -> longValue(args[0].toString());
                case "getBoolean" -> booleanValue(args[0].toString());
                case "getTimestamp" -> timestampValue(args[0].toString());
                case "wasNull" -> lastWasNull;
                case "close" -> null;
                default -> defaultValue(method.getReturnType());
            };
        }

        private Object value(String column) {
            Object value = rows.get(cursor).get(column);
            lastWasNull = value == null;
            return value;
        }

        private String stringValue(String column) {
            Object value = value(column);
            return value == null ? null : value.toString();
        }

        private int intValue(String column) {
            Object value = value(column);
            return value == null ? 0 : ((Number) value).intValue();
        }

        private long longValue(String column) {
            Object value = value(column);
            return value == null ? 0L : ((Number) value).longValue();
        }

        private boolean booleanValue(String column) {
            Object value = value(column);
            return value != null && (Boolean) value;
        }

        private Timestamp timestampValue(String column) {
            Object value = value(column);
            if (value == null) {
                return null;
            }
            if (value instanceof Timestamp timestamp) {
                return timestamp;
            }
            if (value instanceof Instant instant) {
                return Timestamp.from(instant);
            }
            return Timestamp.from(Instant.parse(value.toString()));
        }
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, InvocationHandler handler) {
        return (T)
                Proxy.newProxyInstance(
                        type.getClassLoader(),
                        new Class<?>[] {type},
                        (proxy, method, args) -> {
                            if (method.getDeclaringClass() == Object.class) {
                                return objectMethod(proxy, method, args);
                            }
                            return handler.invoke(proxy, method, args);
                        });
    }

    private static Object objectMethod(Object proxy, Method method, Object[] args) {
        return switch (method.getName()) {
            case "toString" -> proxy.getClass().getInterfaces()[0].getSimpleName() + " proxy";
            case "hashCode" -> System.identityHashCode(proxy);
            case "equals" -> proxy == args[0];
            default -> null;
        };
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) {
            return null;
        }
        if (type == boolean.class) {
            return false;
        }
        if (type == int.class) {
            return 0;
        }
        if (type == long.class) {
            return 0L;
        }
        if (type == float.class) {
            return 0F;
        }
        if (type == double.class) {
            return 0D;
        }
        if (type == byte.class) {
            return (byte) 0;
        }
        if (type == short.class) {
            return (short) 0;
        }
        if (type == char.class) {
            return (char) 0;
        }
        return null;
    }
}
