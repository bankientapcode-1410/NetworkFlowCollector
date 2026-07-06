# API Performance Testing Plan

## Review Result

The original plan is directionally correct, but it has several flaws that would make the test either fail or prove the wrong thing:

- `GET /flows` and the aggregation endpoints require both `start_time` and `end_time`; `/flows?limit=100` returns `400`.
- The sample aggregation window `2023-01-01` to `2024-01-01` will not include newly generated records, because `TrafficGenerator` writes current timestamps.
- Docker Compose defaults `NFC_SURICATA_START_AT_END=true`, so a log file generated before startup is skipped by the Suricata file collector.
- The sample writes `tmp/suricata-10m.json`, but Compose mounts `../suricata-eve.json` unless `NFC_SURICATA_HOST_LOG` is set.
- A global `http_req_duration` threshold can hide one slow endpoint behind faster endpoints. The proof should enforce p95 separately per endpoint.
- Status checks must be thresholds too; otherwise fast `400` or `500` responses can still make latency look good.
- Because the table uses `ReplacingMergeTree` and exact APIs read `flows FINAL`, the evidence should include `count() FROM flows FINAL`, not only physical row count.

Use the corrected plan below.

## Requirement Under Test

Prove the second efficiency requirement:

> API response time < 2 seconds with 10 million records.

Acceptance evidence should show:

1. `flows FINAL` contains 10,000,000 visible records.
2. p95 response time is below 2000 ms for each tested API after warm-up.
3. All tested requests return HTTP 200.

## Step 1: Generate Exactly 10 Million Records

Run from the repository root in PowerShell.

```powershell
New-Item -ItemType Directory -Force tmp | Out-Null

# Remove or archive any old benchmark file first, otherwise TrafficGenerator appends.
# Remove-Item -LiteralPath tmp\suricata-10m.json -Force

javac -d target\manual-generator-classes src\test\java\com\kien\networkflowcollector\TrafficGenerator.java

java -cp target\manual-generator-classes `
  com.kien.networkflowcollector.TrafficGenerator `
  suricata `
  -t tmp\suricata-10m.json `
  -c 10000000 `
  -d 0 `
  -q
```

Notes:

- Use `-q` to avoid printing 10 million log lines.
- The generator appends to the target file. Start from a missing or empty file to make the count exact.
- This file can be several GB. Confirm there is enough disk space before running.

## Step 2: Start the Stack So the File Is Actually Ingested

Set the Compose variables in the same PowerShell session, then start the stack.

```powershell
$env:NFC_SURICATA_HOST_LOG = "../tmp/suricata-10m.json"
$env:NFC_SURICATA_START_AT_END = "false"
$env:NFC_SURICATA_ENABLED = "true"

# Keep other collectors quiet so the count proves this data set.
$env:NFC_ZEEK_ENABLED = "false"
$env:NFC_NETFLOW_ENABLED = "false"

# Clean once for a fresh benchmark. Do not restart the app with this still true after loading.
$env:CLICKHOUSE_CLEAN_ON_START = "true"

docker compose -f deploy\docker-compose.yml up -d --build
```

Wait until ingestion finishes. Check both physical and exact visible row counts:

```powershell
docker compose -f deploy\docker-compose.yml exec -T clickhouse `
  clickhouse-client --user kien --password 2606 `
  --query "SELECT count() AS physical_rows FROM flows"

docker compose -f deploy\docker-compose.yml exec -T clickhouse `
  clickhouse-client --user kien --password 2606 `
  --query "SELECT count() AS exact_visible_rows FROM flows FINAL"

docker compose -f deploy\docker-compose.yml exec -T clickhouse `
  clickhouse-client --user kien --password 2606 `
  --query "SELECT min(ts_start), max(ts_start) FROM flows FINAL"
```

Use the `min(ts_start)` and `max(ts_start)` values to choose a benchmark window that includes the generated data. For freshly generated data, a current UTC window around the run time is usually enough.

## Step 3: Run the k6 API Load Test

The reusable k6 script is:

```text
tools/perf/api-response-time-10m.k6.js
```

Example run:

```powershell
$env:BASE_URL = "http://localhost:8080"
$env:START_TIME = "2026-07-06T00:00:00Z"
$env:END_TIME = "2026-07-07T00:00:00Z"
$env:VUS = "50"
$env:DURATION = "1m"

k6 run tools\perf\api-response-time-10m.k6.js
```

For a stronger run, increase concurrency and duration:

```powershell
$env:VUS = "100"
$env:DURATION = "2m"
k6 run tools\perf\api-response-time-10m.k6.js
```

The script tests these endpoints with separate p95 thresholds:

- `GET /flows`
- `GET /flows/aggregations/top-ports`
- `GET /flows/aggregations/top-talkers`

It also fails the run if any status check fails.
It also fails if the selected time window returns empty flow data or empty aggregation buckets.

## Step 4: Report the Evidence

Capture these items for the report:

1. `SELECT count() FROM flows FINAL` output showing 10,000,000 records.
2. k6 summary showing `p(95)<2000` for each endpoint tag.
3. k6 `checks` rate at 100% and `http_req_failed` at 0%.
4. Hardware/context: CPU, RAM, Docker/ClickHouse settings, VUS, duration, and exact time window.

This makes the result defensible: the data set is real, the query window hits that data, each API is measured separately, and error responses cannot masquerade as fast responses.
