CREATE TABLE IF NOT EXISTS flows
(
    flow_id UUID,
    ts_start DateTime64(3, 'UTC'),
    ts_end DateTime64(3, 'UTC'),
    duration_ms UInt64,
    src_ip IPv6,
    src_port UInt16,
    dst_ip IPv6,
    dst_port UInt16,
    protocol LowCardinality(String),
    bytes_total UInt64,
    packets_total UInt64,
    tcp_flags Nullable(UInt16),
    sampled Bool,
    sampling_rate Nullable(UInt64),
    sample_pool Nullable(UInt64),
    source_type LowCardinality(String),
    exporter_ip IPv6,
    src_country_code Nullable(FixedString(2)),
    src_asn Nullable(UInt32),
    src_as_org Nullable(String),
    dst_country_code Nullable(FixedString(2)),
    dst_asn Nullable(UInt32),
    dst_as_org Nullable(String),
    ingest_time DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(ingest_time)
PARTITION BY toYYYYMMDD(ts_start)
ORDER BY (toStartOfHour(ts_start), src_ip, dst_ip, dst_port, ts_start, flow_id)
TTL toDateTime(ts_start) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

ALTER TABLE flows ADD INDEX IF NOT EXISTS idx_src_ip src_ip TYPE bloom_filter(0.01) GRANULARITY 4;
ALTER TABLE flows ADD INDEX IF NOT EXISTS idx_dst_ip dst_ip TYPE bloom_filter(0.01) GRANULARITY 4;
ALTER TABLE flows ADD INDEX IF NOT EXISTS idx_flow_id flow_id TYPE bloom_filter(0.01) GRANULARITY 1;
