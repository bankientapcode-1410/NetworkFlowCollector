package com.kien.networkflowcollector.storage.clickhouse;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.common.IpAddressSupport;
import com.kien.networkflowcollector.storage.AggBucket;
import com.kien.networkflowcollector.storage.AggQuery;
import com.kien.networkflowcollector.storage.FlowCursor;
import com.kien.networkflowcollector.storage.FlowQuery;
import com.kien.networkflowcollector.storage.FlowSlice;
import com.kien.networkflowcollector.storage.FlowStore;
import com.kien.networkflowcollector.storage.RetryableStorageException;
import com.kien.networkflowcollector.storage.WriteReceipt;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoField;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

public class ClickHouseFlowStore implements FlowStore {

    private static final int DEFAULT_QUERY_LIMIT = 50;
    private static final int MAX_QUERY_LIMIT = 1000;
    private static final int DEFAULT_AGG_LIMIT = 10;
    private static final int MAX_AGG_LIMIT = 100;
    private static final DateTimeFormatter CLICKHOUSE_TIMESTAMP_FORMATTER =
            new DateTimeFormatterBuilder()
                    .appendPattern("yyyy-MM-dd HH:mm:ss")
                    .appendFraction(ChronoField.MILLI_OF_SECOND, 3, 3, true)
                    .toFormatter(Locale.ROOT)
                    .withZone(ZoneOffset.UTC);

    private static final String SELECT_COLUMNS =
            """
            flow_id, ts_start, ts_end, duration_ms, src_ip, src_port, dst_ip, dst_port,
            protocol, bytes_total, packets_total, tcp_flags, sampled, sampling_rate,
            sample_pool, source_type, exporter_ip, src_country_code, src_asn, src_as_org,
            dst_country_code, dst_asn, dst_as_org, ingest_time
            """;

    private static final String INSERT_SQL =
            """
            INSERT INTO flows (
                flow_id, ts_start, ts_end, duration_ms, src_ip, src_port, dst_ip, dst_port,
                protocol, bytes_total, packets_total, tcp_flags, sampled, sampling_rate,
                sample_pool, source_type, exporter_ip, src_country_code, src_asn, src_as_org,
                dst_country_code, dst_asn, dst_as_org, ingest_time
            ) VALUES (?, ?, ?, ?, toIPv6(?), ?, toIPv6(?), ?, ?, ?, ?, ?, ?, ?, ?, ?, toIPv6(?), ?, ?, ?, ?, ?, ?, ?)
            """;
    private static final String TRUNCATE_SQL = "TRUNCATE TABLE IF EXISTS flows";

    private final ConnectionProvider connectionProvider;

    public ClickHouseFlowStore(ClickHouseProperties properties) {
        this(properties, driverManagerProvider(properties));
    }

    ClickHouseFlowStore(ClickHouseProperties properties, ConnectionProvider connectionProvider) {
        Objects.requireNonNull(properties, "properties");
        this.connectionProvider = Objects.requireNonNull(connectionProvider, "connectionProvider");
    }

    private static ConnectionProvider driverManagerProvider(ClickHouseProperties properties) {
        Objects.requireNonNull(properties, "properties");
        return () ->
                DriverManager.getConnection(
                        properties.getUrl(), properties.getUser(), properties.getPassword());
    }

    public void truncate() {
        try (Connection connection = connectionProvider.getConnection();
                Statement statement = connection.createStatement()) {
            statement.execute(TRUNCATE_SQL);
        } catch (SQLException e) {
            throw new RetryableStorageException("ClickHouse truncate failed", e);
        }
    }

    @Override
    public WriteReceipt batchInsert(List<NormalizedFlow> flows) {
        if (flows == null || flows.isEmpty()) {
            return new WriteReceipt(0, Instant.now());
        }

        try (Connection connection = connectionProvider.getConnection();
                PreparedStatement statement = connection.prepareStatement(INSERT_SQL)) {
            for (NormalizedFlow flow : flows) {
                bind(statement, flow);
                statement.addBatch();
            }
            verifyBatchResult(statement.executeBatch());
            return new WriteReceipt(flows.size(), Instant.now());
        } catch (SQLException e) {
            throw new RetryableStorageException("ClickHouse batch insert failed", e);
        }
    }

    @Override
    public FlowSlice<NormalizedFlow> query(FlowQuery filter, FlowCursor cursor) {
        Objects.requireNonNull(filter, "filter");
        validateTimeRange(filter.from(), filter.to());
        validateCursor(cursor);

        int limit = queryLimit(filter, cursor);
        QuerySpec spec = flowQuery(filter, cursor, limit + 1);

        try (Connection connection = connectionProvider.getConnection();
                PreparedStatement statement = connection.prepareStatement(spec.sql())) {
            bindParameters(statement, spec.parameters());
            try (ResultSet resultSet = statement.executeQuery()) {
                List<NormalizedFlow> rows = new ArrayList<>(limit + 1);
                while (resultSet.next()) {
                    rows.add(mapFlow(resultSet));
                }

                boolean hasMore = rows.size() > limit;
                List<NormalizedFlow> page =
                        hasMore ? List.copyOf(rows.subList(0, limit)) : List.copyOf(rows);
                Optional<FlowCursor> nextCursor = Optional.empty();
                if (hasMore && !page.isEmpty()) {
                    NormalizedFlow last = page.get(page.size() - 1);
                    nextCursor = Optional.of(new FlowCursor(last.tsStart(), last.flowId(), limit));
                }
                return new FlowSlice<>(page, nextCursor, hasMore);
            }
        } catch (SQLException e) {
            throw new RetryableStorageException("ClickHouse flow query failed", e);
        }
    }

    @Override
    public Optional<NormalizedFlow> findById(UUID flowId) {
        Objects.requireNonNull(flowId, "flowId");

        String sql =
                "SELECT "
                        + SELECT_COLUMNS
                        + " FROM flows FINAL WHERE flow_id = ? ORDER BY ingest_time DESC LIMIT 1";
        try (Connection connection = connectionProvider.getConnection();
                PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setObject(1, flowId);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next()) {
                    return Optional.empty();
                }
                return Optional.of(mapFlow(resultSet));
            }
        } catch (SQLException e) {
            throw new RetryableStorageException("ClickHouse flow lookup failed", e);
        }
    }

    @Override
    public List<AggBucket> topTalkers(AggQuery query) {
        return aggregate(query, "toString(src_ip)", "ClickHouse top talkers query failed");
    }

    @Override
    public List<AggBucket> topPorts(AggQuery query) {
        return aggregate(query, "toString(dst_port)", "ClickHouse top ports query failed");
    }

    private static void bind(PreparedStatement statement, NormalizedFlow flow) throws SQLException {
        int index = 1;
        statement.setObject(index++, flow.flowId());
        setInstant(statement, index++, flow.tsStart());
        setInstant(statement, index++, flow.tsEnd());
        statement.setLong(index++, flow.durationMs());
        statement.setString(index++, flow.srcIp());
        statement.setInt(index++, flow.srcPort());
        statement.setString(index++, flow.dstIp());
        statement.setInt(index++, flow.dstPort());
        statement.setString(index++, flow.protocol());
        statement.setLong(index++, flow.bytesTotal());
        statement.setLong(index++, flow.packetsTotal());
        setNullableInteger(statement, index++, flow.tcpFlags());
        statement.setBoolean(index++, flow.sampled());
        setNullableLong(statement, index++, flow.samplingRate());
        setNullableLong(statement, index++, flow.samplePool());
        statement.setString(index++, flow.sourceType());
        statement.setString(index++, flow.exporterIp());
        setNullableString(statement, index++, flow.srcCountryCode());
        setNullableLong(statement, index++, flow.srcAsn());
        setNullableString(statement, index++, flow.srcAsOrg());
        setNullableString(statement, index++, flow.dstCountryCode());
        setNullableLong(statement, index++, flow.dstAsn());
        setNullableString(statement, index++, flow.dstAsOrg());
        setInstant(statement, index, flow.ingestTime());
    }

    private static void verifyBatchResult(int[] updateCounts) throws SQLException {
        for (int updateCount : updateCounts) {
            if (updateCount == Statement.EXECUTE_FAILED) {
                throw new SQLException("ClickHouse batch insert reported a failed row");
            }
        }
    }

    private static void setNullableString(PreparedStatement statement, int index, String value)
            throws SQLException {
        if (value == null) {
            statement.setNull(index, Types.VARCHAR);
        } else {
            statement.setString(index, value);
        }
    }

    private static void setNullableInteger(PreparedStatement statement, int index, Integer value)
            throws SQLException {
        if (value == null) {
            statement.setNull(index, Types.INTEGER);
        } else {
            statement.setInt(index, value);
        }
    }

    private static void setNullableLong(PreparedStatement statement, int index, Long value)
            throws SQLException {
        if (value == null) {
            statement.setNull(index, Types.BIGINT);
        } else {
            statement.setLong(index, value);
        }
    }

    private List<AggBucket> aggregate(AggQuery query, String keyExpression, String failureMessage) {
        Objects.requireNonNull(query, "query");
        validateTimeRange(query.from(), query.to());

        int limit = normalizeLimit(query.limit(), DEFAULT_AGG_LIMIT, MAX_AGG_LIMIT, "aggregation limit");
        String orderColumn = orderColumn(query.metric());
        String sql =
                """
                SELECT %s AS bucket_key,
                       count() AS flow_count,
                       sum(bytes_total) AS bytes_total,
                       sum(packets_total) AS packets_total
                FROM flows FINAL
                WHERE ts_start >= ? AND ts_start < ?
                GROUP BY bucket_key
                ORDER BY %s DESC, bucket_key ASC
                LIMIT ?
                """
                        .formatted(keyExpression, orderColumn);

        try (Connection connection = connectionProvider.getConnection();
                PreparedStatement statement = connection.prepareStatement(sql)) {
            setInstant(statement, 1, query.from());
            setInstant(statement, 2, query.to());
            statement.setInt(3, limit);
            try (ResultSet resultSet = statement.executeQuery()) {
                List<AggBucket> buckets = new ArrayList<>();
                while (resultSet.next()) {
                    buckets.add(new AggBucket(
                            resultSet.getString("bucket_key"),
                            resultSet.getLong("flow_count"),
                            resultSet.getLong("bytes_total"),
                            resultSet.getLong("packets_total")));
                }
                return List.copyOf(buckets);
            }
        } catch (SQLException e) {
            throw new RetryableStorageException(failureMessage, e);
        }
    }

    private static QuerySpec flowQuery(FlowQuery filter, FlowCursor cursor, int rowLimit) {
        StringBuilder sql = new StringBuilder("SELECT ");
        sql.append(SELECT_COLUMNS);
        sql.append(" FROM flows FINAL WHERE ts_start >= ? AND ts_start < ?");

        List<SqlParameter> parameters = new ArrayList<>();
        parameters.add(SqlParameter.string(formatInstant(filter.from())));
        parameters.add(SqlParameter.string(formatInstant(filter.to())));

        appendIpFilter(sql, parameters, "src_ip", filter.srcIp());
        appendIntegerFilter(sql, parameters, "src_port", filter.srcPort());
        appendIpFilter(sql, parameters, "dst_ip", filter.dstIp());
        appendIntegerFilter(sql, parameters, "dst_port", filter.dstPort());
        appendStringFilter(sql, parameters, "protocol", normalizedProtocol(filter.protocol()));
        appendStringFilter(sql, parameters, "source_type", textOrNull(filter.sourceType()));

        if (cursor != null) {
            sql.append(" AND (ts_start, flow_id) < (?, ?)");
            parameters.add(SqlParameter.string(formatInstant(cursor.tsStart())));
            parameters.add(SqlParameter.uuid(cursor.flowId()));
        }

        sql.append(" ORDER BY ts_start DESC, flow_id DESC LIMIT ?");
        parameters.add(SqlParameter.integer(rowLimit));
        return new QuerySpec(sql.toString(), parameters);
    }

    private static void appendIpFilter(
            StringBuilder sql, List<SqlParameter> parameters, String column, String value) {
        String text = textOrNull(value);
        if (text == null) {
            return;
        }
        if (text.contains("/")) {
            validateCidr(column, text);
            sql.append(" AND isIPAddressInRange(toString(").append(column).append("), ?)");
        } else {
            validateIpLiteral(column, text);
            sql.append(" AND ").append(column).append(" = toIPv6(?)");
        }
        parameters.add(SqlParameter.string(text));
    }

    private static void appendIntegerFilter(
            StringBuilder sql, List<SqlParameter> parameters, String column, Integer value) {
        if (value == null) {
            return;
        }
        sql.append(" AND ").append(column).append(" = ?");
        parameters.add(SqlParameter.integer(value));
    }

    private static void appendStringFilter(
            StringBuilder sql, List<SqlParameter> parameters, String column, String value) {
        if (value == null) {
            return;
        }
        sql.append(" AND ").append(column).append(" = ?");
        parameters.add(SqlParameter.string(value));
    }

    private static String orderColumn(AggQuery.Metric metric) {
        return switch (metric) {
            case BYTES -> "bytes_total";
            case PACKETS -> "packets_total";
            case FLOWS -> "flow_count";
        };
    }

    private static void bindParameters(PreparedStatement statement, List<SqlParameter> parameters)
            throws SQLException {
        for (int i = 0; i < parameters.size(); i++) {
            SqlParameter parameter = parameters.get(i);
            int index = i + 1;
            switch (parameter.kind()) {
                case STRING -> statement.setString(index, (String) parameter.value());
                case INTEGER -> statement.setInt(index, (Integer) parameter.value());
                case UUID -> statement.setObject(index, parameter.value());
            }
        }
    }

    private static NormalizedFlow mapFlow(ResultSet resultSet) throws SQLException {
        return new NormalizedFlow(
                uuid(resultSet, "flow_id"),
                instant(resultSet, "ts_start"),
                instant(resultSet, "ts_end"),
                resultSet.getLong("duration_ms"),
                ipString(resultSet, "src_ip"),
                resultSet.getInt("src_port"),
                ipString(resultSet, "dst_ip"),
                resultSet.getInt("dst_port"),
                resultSet.getString("protocol"),
                resultSet.getLong("bytes_total"),
                resultSet.getLong("packets_total"),
                nullableInteger(resultSet, "tcp_flags"),
                resultSet.getBoolean("sampled"),
                nullableLong(resultSet, "sampling_rate"),
                nullableLong(resultSet, "sample_pool"),
                resultSet.getString("source_type"),
                ipString(resultSet, "exporter_ip"),
                resultSet.getString("src_country_code"),
                nullableLong(resultSet, "src_asn"),
                resultSet.getString("src_as_org"),
                resultSet.getString("dst_country_code"),
                nullableLong(resultSet, "dst_asn"),
                resultSet.getString("dst_as_org"),
                instant(resultSet, "ingest_time"));
    }

    private static UUID uuid(ResultSet resultSet, String column) throws SQLException {
        Object value = resultSet.getObject(column);
        if (value instanceof UUID uuid) {
            return uuid;
        }
        return UUID.fromString(value.toString());
    }

    private static String ipString(ResultSet resultSet, String column) throws SQLException {
        Object value = resultSet.getObject(column);
        if (value instanceof InetAddress address) {
            return address.getHostAddress();
        }
        if (value instanceof byte[] bytes) {
            try {
                return InetAddress.getByAddress(bytes).getHostAddress();
            } catch (UnknownHostException e) {
                throw new SQLException("Unable to parse ClickHouse IP column: " + column, e);
            }
        }
        if (value != null) {
            return value.toString();
        }
        return resultSet.getString(column);
    }

    private static Instant instant(ResultSet resultSet, String column) throws SQLException {
        Object value = resultSet.getObject(column);
        if (value instanceof Instant instant) {
            return instant;
        }
        if (value instanceof OffsetDateTime offsetDateTime) {
            return offsetDateTime.toInstant();
        }
        if (value instanceof ZonedDateTime zonedDateTime) {
            return zonedDateTime.toInstant();
        }
        if (value instanceof Timestamp timestamp) {
            return timestamp.toInstant();
        }
        if (value instanceof LocalDateTime localDateTime) {
            return localDateTime.toInstant(ZoneOffset.UTC);
        }
        if (value != null) {
            return parseInstant(value.toString());
        }
        Timestamp timestamp = resultSet.getTimestamp(column);
        if (timestamp == null) {
            throw new SQLException("Column " + column + " is null");
        }
        return timestamp.toInstant();
    }

    private static Instant parseInstant(String value) throws SQLException {
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException ignored) {
            String normalized = value.trim().replace(' ', 'T');
            if (!normalized.endsWith("Z")) {
                normalized = normalized + "Z";
            }
            try {
                return Instant.parse(normalized);
            } catch (DateTimeParseException e) {
                throw new SQLException("Unable to parse ClickHouse timestamp: " + value, e);
            }
        }
    }

    private static Integer nullableInteger(ResultSet resultSet, String column) throws SQLException {
        int value = resultSet.getInt(column);
        return resultSet.wasNull() ? null : value;
    }

    private static Long nullableLong(ResultSet resultSet, String column) throws SQLException {
        long value = resultSet.getLong(column);
        return resultSet.wasNull() ? null : value;
    }

    private static int queryLimit(FlowQuery filter, FlowCursor cursor) {
        int requested = filter.limit();
        if (requested <= 0 && cursor != null) {
            requested = cursor.limit();
        }
        return normalizeLimit(requested, DEFAULT_QUERY_LIMIT, MAX_QUERY_LIMIT, "query limit");
    }

    private static int normalizeLimit(int requested, int defaultLimit, int maxLimit, String label) {
        if (requested <= 0) {
            return defaultLimit;
        }
        if (requested > maxLimit) {
            throw new IllegalArgumentException(label + " must be <= " + maxLimit);
        }
        return requested;
    }

    private static void validateTimeRange(Instant from, Instant to) {
        if (from == null || to == null) {
            throw new IllegalArgumentException("from and to are required");
        }
        if (!from.isBefore(to)) {
            throw new IllegalArgumentException("from must be before to");
        }
    }

    private static void validateCursor(FlowCursor cursor) {
        if (cursor == null) {
            return;
        }
        if (cursor.tsStart() == null || cursor.flowId() == null) {
            throw new IllegalArgumentException("cursor requires tsStart and flowId");
        }
    }

    private static void setInstant(PreparedStatement statement, int index, Instant value)
            throws SQLException {
        statement.setString(index, formatInstant(value));
    }

    private static String formatInstant(Instant value) {
        return CLICKHOUSE_TIMESTAMP_FORMATTER.format(value);
    }

    private static void validateIpLiteral(String column, String value) {
        if (!IpAddressSupport.isIpLiteral(value)) {
            throw new IllegalArgumentException(column + " must be an IP literal");
        }
    }

    private static void validateCidr(String column, String value) {
        if (!IpAddressSupport.isCidr(value)) {
            throw new IllegalArgumentException(column + " must be an IP literal or CIDR range");
        }
    }

    private static String normalizedProtocol(String value) {
        String text = textOrNull(value);
        return text == null ? null : text.toLowerCase(Locale.ROOT);
    }

    private static String textOrNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }

    @FunctionalInterface
    interface ConnectionProvider {
        Connection getConnection() throws SQLException;
    }

    private record QuerySpec(String sql, List<SqlParameter> parameters) {}

    private record SqlParameter(SqlParameterKind kind, Object value) {
        static SqlParameter string(String value) {
            return new SqlParameter(SqlParameterKind.STRING, value);
        }

        static SqlParameter integer(Integer value) {
            return new SqlParameter(SqlParameterKind.INTEGER, value);
        }

        static SqlParameter uuid(UUID value) {
            return new SqlParameter(SqlParameterKind.UUID, value);
        }
    }

    private enum SqlParameterKind {
        STRING,
        INTEGER,
        UUID
    }
}
