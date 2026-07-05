# Mock Flow Tools

Use these checks when you want synthetic flow traffic without starting the full pipeline.

## Collector-only mixed-flow test

This verifies the collectors can keep mixed source types separated without Kafka, ClickHouse, or the Spring app:

```powershell
.\mvnw.cmd -Dtest=CollectorOnlyMixedFlowTest test
```

The test creates random Suricata EVE, Zeek conn, and NetFlow v5 inputs, starts only those collectors, publishes into an in-memory `FlowPublisher`, and asserts the emitted `sourceType` counts:

- `suricata-flow`
- `zeek-conn`
- `netflow-v5`

## Traffic generator smoke test

This checks whether the Java traffic generator can write Suricata/Zeek files and send NetFlow v5 UDP packets:

```powershell
.\mvnw.cmd -Dtest=TrafficGeneratorSmokeTest test
```

## Manual generator commands

Compile the generator:

```powershell
New-Item -ItemType Directory -Force target\manual-generator-classes
javac -d target\manual-generator-classes src\test\java\com\kien\networkflowcollector\TrafficGenerator.java
```

Generate file-based test inputs:

```powershell
java -cp target\manual-generator-classes com.kien.networkflowcollector.TrafficGenerator suricata -t tmp\suricata-eve.json -c 20 -d 0
java -cp target\manual-generator-classes com.kien.networkflowcollector.TrafficGenerator zeek -t tmp\conn.log -c 20 -d 0
```

Send NetFlow v5 to a collector listening on UDP 2055:

```powershell
java -cp target\manual-generator-classes com.kien.networkflowcollector.TrafficGenerator netflow -t 127.0.0.1:2055 -c 20 -d 0
```

Generate a mixed run:

```powershell
java -cp target\manual-generator-classes com.kien.networkflowcollector.TrafficGenerator mix `
  --suricata-target tmp\suricata-eve.json `
  --zeek-target tmp\conn.log `
  --netflow-target 127.0.0.1:2055 `
  -c 100 -d 0
```

For collector-only testing, prefer the Maven tests above. The manual commands are useful when you want to see files/UDP packets being produced.
