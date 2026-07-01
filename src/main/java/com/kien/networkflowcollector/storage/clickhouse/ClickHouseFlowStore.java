package com.kien.networkflowcollector.storage.clickhouse;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.storage.AggBucket;
import com.kien.networkflowcollector.storage.AggQuery;
import com.kien.networkflowcollector.storage.FlowCursor;
import com.kien.networkflowcollector.storage.FlowQuery;
import com.kien.networkflowcollector.storage.FlowSlice;
import com.kien.networkflowcollector.storage.FlowStore;
import com.kien.networkflowcollector.storage.RetryableStorageException;
import com.kien.networkflowcollector.storage.WriteReceipt;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Types;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public class ClickHouseFlowStore implements FlowStore {

    private static final String INSERT_SQL =
            """
            INSERT INTO flows (
                flow_id, ts_start, ts_end, duration_ms, src_ip, src_port, dst_ip, dst_port,
                protocol, bytes_total, packets_total, tcp_flags, sampled, sampling_rate,
                sample_pool, source_type, exporter_ip, src_country_code, src_asn, src_as_org,
                dst_country_code, dst_asn, dst_as_org, ingest_time
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;

    private final ClickHouseProperties properties;

    public ClickHouseFlowStore(ClickHouseProperties properties) {
        this.properties = properties;
    }

    @Override
    public WriteReceipt batchInsert(List<NormalizedFlow> flows) {
        if (flows == null || flows.isEmpty()) {
            return new WriteReceipt(0, Instant.now());
        }

        try (Connection connection =
                        DriverManager.getConnection(
                                properties.getUrl(), properties.getUser(), properties.getPassword());
                PreparedStatement statement = connection.prepareStatement(INSERT_SQL)) {
            for (NormalizedFlow flow : flows) {
                bind(statement, flow);
                statement.addBatch();
            }
            statement.executeBatch();
            return new WriteReceipt(flows.size(), Instant.now());
        } catch (SQLException e) {
            throw new RetryableStorageException("ClickHouse batch insert failed", e);
        }
    }

    @Override
    public FlowSlice<NormalizedFlow> query(FlowQuery filter, FlowCursor cursor) {
        throw new UnsupportedOperationException("ClickHouse flow query is not implemented yet");
    }

    @Override
    public Optional<NormalizedFlow> findById(UUID flowId) {
        throw new UnsupportedOperationException("ClickHouse flow lookup is not implemented yet");
    }

    @Override
    public List<AggBucket> topTalkers(AggQuery query) {
        throw new UnsupportedOperationException("ClickHouse top talkers query is not implemented yet");
    }

    @Override
    public List<AggBucket> topPorts(AggQuery query) {
        throw new UnsupportedOperationException("ClickHouse top ports query is not implemented yet");
    }

    private static void bind(PreparedStatement statement, NormalizedFlow flow) throws SQLException {
        int index = 1;
        statement.setObject(index++, flow.flowId());
        statement.setString(index++, flow.tsStart().toString());
        statement.setString(index++, flow.tsEnd().toString());
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
        statement.setString(index, flow.ingestTime().toString());
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
}
