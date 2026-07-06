package com.kien.networkflowcollector;

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Standalone traffic generator for testing the Network Flow Collector.
 * <p>
 * Generates synthetic Suricata EVE, Zeek conn, NetFlow v5/v9, and REST API
 * ingest records — the same data the Python {@code traffic_generator.py}
 * produced, but implemented in pure Java (no external libs required).
 * <p>
 * <b>Compile &amp; run:</b>
 * <pre>
 *   javac src/test/java/com/kien/networkflowcollector/TrafficGenerator.java
 *   java -cp src/test/java com.kien.networkflowcollector.TrafficGenerator suricata -c 10 -d 1.0
 *   java -cp src/test/java com.kien.networkflowcollector.TrafficGenerator netflow -t 127.0.0.1:2055
 *   java -cp src/test/java com.kien.networkflowcollector.TrafficGenerator netflow-v9 -t 127.0.0.1:2055
 *   java -cp src/test/java com.kien.networkflowcollector.TrafficGenerator mix --ingest-target http://localhost:8080/ingest
 * </pre>
 */
public class TrafficGenerator {

    private static final int MAX_NETFLOW_V5_RECORDS = 30;
    private static final int DEFAULT_INGEST_BATCH_SIZE = 500;
    private static final int MIX_PACE_BATCH_RECORDS = 100;
    private static final long SPIN_SLEEP_THRESHOLD_NANOS = 1_000_000L;
    private static final String[] DEFAULT_MIX_TYPES = {"suricata", "zeek", "netflow-v5", "netflow-v9", "ingest"};
    private static final int[] SAMPLE_RATES = {100, 500, 1000};
    private static final int[][] PRIVATE_SOURCE_PREFIXES = {
        {192, 168, 1}, {10, 20, 30}, {172, 16, 1}
    };
    private static final int[][] PRIVATE_DESTINATION_PREFIXES = {
        {10, 0, 0}, {10, 1, 0}, {192, 168, 50}
    };
    private static final int[][] ENRICHED_SOURCE_PREFIXES = {
        {8, 8, 8}, {1, 1, 1}, {9, 9, 9}, {17, 0, 0}, {208, 67, 222}
    };
    private static final int[][] ENRICHED_DESTINATION_PREFIXES = {
        {93, 184, 216}, {142, 250, 72}, {104, 16, 132}, {8, 8, 8}, {1, 1, 1}
    };
    private static final Random RNG = ThreadLocalRandom.current();
    private static final DateTimeFormatter ISO_FMT =
            DateTimeFormatter.ISO_INSTANT;

    // ------------------------------------------------------------------ main

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            printUsage();
            System.exit(1);
        }

        String type = args[0];
        Map<String, String> opts = parseArgs(args);

        int count = Integer.parseInt(opts.getOrDefault("count", "10"));
        double delay = Double.parseDouble(opts.getOrDefault("delay", "1.0"));
        double rate = Double.parseDouble(opts.getOrDefault("rate", "0"));
        int batchSize = Integer.parseInt(opts.getOrDefault("batch-size", "1"));
        int ingestBatchSize = Integer.parseInt(opts.getOrDefault("ingest-batch-size", String.valueOf(DEFAULT_INGEST_BATCH_SIZE)));
        boolean quiet = Boolean.parseBoolean(opts.getOrDefault("quiet", "false"));
        RunOptions run = new RunOptions(count, delay, rate, batchSize, quiet);

        String suricataTarget = opts.getOrDefault("suricata-target", "suricata-eve.json");
        String zeekTarget     = opts.getOrDefault("zeek-target", "conn.log");
        String netflowTarget  = opts.getOrDefault("netflow-target", opts.getOrDefault("target", "127.0.0.1:2055"));
        String ingestTarget   = opts.getOrDefault("ingest-target", "http://127.0.0.1:8080/ingest");

        switch (type) {
            case "suricata":
                generateSuricataEve(opts.getOrDefault("target", suricataTarget), run);
                break;
            case "zeek":
                generateZeekConn(opts.getOrDefault("target", zeekTarget), run);
                break;
            case "netflow":
                sendNetflow(
                        opts.getOrDefault("target", netflowTarget),
                        opts.getOrDefault("netflow-version", opts.getOrDefault("version", "5")),
                        run);
                break;
            case "netflow-v5":
                sendNetflowV5(opts.getOrDefault("target", netflowTarget), run);
                break;
            case "netflow-v9":
                sendNetflowV9(opts.getOrDefault("target", netflowTarget), run);
                break;
            case "ingest":
                sendIngestApi(opts.getOrDefault("target", ingestTarget), run);
                break;
            case "mix":
                Map<String, String> targets = new HashMap<>();
                targets.put("suricata", suricataTarget);
                targets.put("zeek", zeekTarget);
                targets.put("netflow", netflowTarget);
                targets.put("ingest", ingestTarget);
                generateMix(run, targets, ingestBatchSize, mixTypes(opts.get("mix-sources")));
                break;
            default:
                System.err.println("Unknown type: " + type);
                printUsage();
                System.exit(1);
        }
    }

    // -------------------------------------------------------------- parsers

    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> opts = new HashMap<>();
        for (int i = 1; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals("-q")) {
                opts.put("quiet", "true");
            } else if (arg.startsWith("--")) {
                String key = arg.substring(2);
                if ("quiet".equals(key)) {
                    opts.put(key, "true");
                } else if (i + 1 < args.length && !args[i + 1].startsWith("-")) {
                    opts.put(key, args[++i]);
                } else {
                    opts.put(key, "true");
                }
            } else if (arg.equals("-t") && i + 1 < args.length) {
                opts.put("target", args[++i]);
            } else if (arg.equals("-c") && i + 1 < args.length) {
                opts.put("count", args[++i]);
            } else if (arg.equals("-d") && i + 1 < args.length) {
                opts.put("delay", args[++i]);
            } else if (arg.equals("-r") && i + 1 < args.length) {
                opts.put("rate", args[++i]);
            }
        }
        return opts;
    }

    private static void printUsage() {
        System.out.println("Usage: com.kien.networkflowcollector.TrafficGenerator <type> [options]");
        System.out.println();
        System.out.println("Types: suricata, zeek, netflow, netflow-v5, netflow-v9, ingest, mix");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  -t, --target <target>          Target (file path or host:port or URL)");
        System.out.println("  -c, --count <n>                Number of flows to generate (default: 10)");
        System.out.println("  -d, --delay <seconds>          Delay between flows in seconds (default: 1.0)");
        System.out.println("  -r, --rate <records/sec>       Target generation rate; overrides --delay when > 0");
        System.out.println("  -q, --quiet                    Suppress per-record/per-packet output");
        System.out.println("  --batch-size <n>               Records per NetFlow v5 packet, max 30 (default: 1)");
        System.out.println("  --suricata-target <file>       Suricata EVE output file (default: suricata-eve.json)");
        System.out.println("  --zeek-target <file>           Zeek conn log output file (default: conn.log)");
        System.out.println("  --netflow-target <host:port>   NetFlow v5/v9 UDP target (default: 127.0.0.1:2055)");
        System.out.println("  --netflow-version <5|9>        Version for type netflow (default: 5)");
        System.out.println("  --ingest-target <url>          REST ingest API URL (default: http://127.0.0.1:8080/ingest)");
        System.out.println("  --ingest-batch-size <n>        REST records per request in mix mode (default: 500)");
        System.out.println("  --mix-sources <csv>            Source types for mix mode (default: all)");
    }

    // ------------------------------------------------------------ Suricata

    private static void generateSuricataEve(String target, RunOptions run) throws Exception {
        try (FileWriter fw = new FileWriter(target, true);
             BufferedWriter bw = new BufferedWriter(fw)) {
            Pacer pacer = new Pacer(run);
            for (int i = 0; i < run.count(); i++) {
                writeSuricataRecord(bw, target, run, i);
                pacer.afterRecords(1);
            }
        }
    }

    // --------------------------------------------------------------- Zeek

    private static void generateZeekConn(String target, RunOptions run) throws Exception {
        try (FileWriter fw = new FileWriter(target, true);
             BufferedWriter bw = new BufferedWriter(fw)) {
            Pacer pacer = new Pacer(run);
            for (int i = 0; i < run.count(); i++) {
                writeZeekRecord(bw, target, run, i);
                pacer.afterRecords(1);
            }
        }
    }

    // ----------------------------------------------------------- NetFlow v5

    private static void sendNetflow(String target, String version, RunOptions run) throws Exception {
        if ("9".equals(version) || "v9".equalsIgnoreCase(version) || "netflow-v9".equalsIgnoreCase(version)) {
            sendNetflowV9(target, run);
        } else if ("5".equals(version) || "v5".equalsIgnoreCase(version) || "netflow-v5".equalsIgnoreCase(version)) {
            sendNetflowV5(target, run);
        } else {
            throw new IllegalArgumentException("Unsupported NetFlow generator version: " + version);
        }
    }

    private static void sendNetflowV5(String target, RunOptions run) throws Exception {
        String[] parts = target.split(":");
        String host = parts[0];
        int port = parts.length > 1 ? Integer.parseInt(parts[1]) : 2055;

        try (DatagramSocket sock = new DatagramSocket()) {
            InetAddress addr = InetAddress.getByName(host);
            Pacer pacer = new Pacer(run);
            int sentRecords = 0;
            int batchSize = run.netflowV5BatchSize();

            while (sentRecords < run.count()) {
                int recordsInPacket = Math.min(batchSize, run.count() - sentRecords);
                sendNetflowV5Packet(sock, addr, host, port, sentRecords, recordsInPacket, run.quiet());
                sentRecords += recordsInPacket;
                pacer.afterRecords(recordsInPacket);
            }
        }
    }

    // ----------------------------------------------------------- NetFlow v9

    private static void sendNetflowV9(String target, RunOptions run) throws Exception {
        String[] parts = target.split(":");
        String host = parts[0];
        int port = parts.length > 1 ? Integer.parseInt(parts[1]) : 2055;

        try (DatagramSocket sock = new DatagramSocket()) {
            InetAddress addr = InetAddress.getByName(host);
            Pacer pacer = new Pacer(run);

            for (int i = 0; i < run.count(); i++) {
                sendNetflowV9Packet(sock, addr, host, port, i, run.quiet());
                pacer.afterRecords(1);
            }
        }
    }

    // --------------------------------------------------------- REST Ingest

    private static void sendIngestApi(String target, RunOptions run) throws Exception {
        if (!target.startsWith("http")) {
            target = "http://" + target;
        }

        Pacer pacer = new Pacer(run);
        URL url = new URL(target);
        for (int i = 0; i < run.count(); i++) {
            sendIngestBatch(url, target, List.of(restRecordJson(i)), run.quiet());
            pacer.afterRecords(1);
        }
    }

    // ----------------------------------------------------------------- Mix

    private static void generateMix(
            RunOptions run, Map<String, String> targets, int ingestBatchSize, String[] types) throws Exception {
        List<String> initialTypes = new ArrayList<>(Arrays.asList(types));
        Collections.shuffle(initialTypes, RNG);
        Pacer pacer = new Pacer(run);
        String suricataTarget = targets.get("suricata");
        String zeekTarget = targets.get("zeek");
        NetflowTarget netflowTarget = netflowTarget(targets.get("netflow"));
        String ingestTarget = httpTarget(targets.get("ingest"));
        URL ingestUrl = new URL(ingestTarget);
        int restBatchSize = Math.max(1, ingestBatchSize);

        try (BufferedWriter suricataWriter = new BufferedWriter(new FileWriter(suricataTarget, true));
             BufferedWriter zeekWriter = new BufferedWriter(new FileWriter(zeekTarget, true));
             DatagramSocket netflowSocket = new DatagramSocket()) {
            int pendingV5Records = 0;
            int v5Sequence = 0;
            int v9Sequence = 0;
            int pendingPaceRecords = 0;
            List<String> pendingRestRecords = new ArrayList<>(restBatchSize);

            for (int i = 0; i < run.count(); i++) {
                String t = i < initialTypes.size() ? initialTypes.get(i) : types[RNG.nextInt(types.length)];
                switch (t) {
                    case "suricata":
                        writeSuricataRecord(suricataWriter, suricataTarget, run, i);
                        break;
                    case "zeek":
                        writeZeekRecord(zeekWriter, zeekTarget, run, i);
                        break;
                    case "netflow-v5":
                        pendingV5Records++;
                        if (pendingV5Records >= run.netflowV5BatchSize()) {
                            sendNetflowV5Packet(
                                    netflowSocket,
                                    netflowTarget.address(),
                                    netflowTarget.host(),
                                    netflowTarget.port(),
                                    v5Sequence,
                                    pendingV5Records,
                                    run.quiet());
                            v5Sequence += pendingV5Records;
                            pendingV5Records = 0;
                        }
                        break;
                    case "netflow-v9":
                        sendNetflowV9Packet(
                                netflowSocket,
                                netflowTarget.address(),
                                netflowTarget.host(),
                                netflowTarget.port(),
                                v9Sequence++,
                                run.quiet());
                        break;
                    case "ingest":
                        pendingRestRecords.add(restRecordJson(i));
                        if (pendingRestRecords.size() >= restBatchSize) {
                            sendIngestBatch(ingestUrl, ingestTarget, pendingRestRecords, run.quiet());
                            pendingRestRecords.clear();
                        }
                        break;
                    default:
                        throw new IllegalArgumentException("Unsupported mix source type: " + t);
                }
                if (run.rate() > 0) {
                    pendingPaceRecords++;
                    if (pendingPaceRecords >= MIX_PACE_BATCH_RECORDS) {
                        pacer.afterRecords(pendingPaceRecords);
                        pendingPaceRecords = 0;
                    }
                } else {
                    pacer.afterRecords(1);
                }
            }

            if (pendingPaceRecords > 0) {
                pacer.afterRecords(pendingPaceRecords);
            }
            if (pendingV5Records > 0) {
                sendNetflowV5Packet(
                        netflowSocket,
                        netflowTarget.address(),
                        netflowTarget.host(),
                        netflowTarget.port(),
                        v5Sequence,
                        pendingV5Records,
                        run.quiet());
            }
            if (!pendingRestRecords.isEmpty()) {
                sendIngestBatch(ingestUrl, ingestTarget, pendingRestRecords, run.quiet());
            }
            suricataWriter.flush();
            zeekWriter.flush();
        }
    }

    // ------------------------------------------------------------ Helpers

    private record RunOptions(int count, double delay, double rate, int batchSize, boolean quiet) {

        private RunOptions {
            if (count < 0) {
                throw new IllegalArgumentException("count must be >= 0");
            }
            if (delay < 0) {
                throw new IllegalArgumentException("delay must be >= 0");
            }
            if (rate < 0) {
                throw new IllegalArgumentException("rate must be >= 0");
            }
            batchSize = Math.max(1, batchSize);
        }

        private int netflowV5BatchSize() {
            return Math.min(MAX_NETFLOW_V5_RECORDS, batchSize);
        }

    }

    private static final class Pacer {

        private final RunOptions options;
        private final long startedAtNanos;
        private long generatedRecords;

        private Pacer(RunOptions options) {
            this.options = options;
            this.startedAtNanos = System.nanoTime();
        }

        private void afterRecords(int records) {
            if (records <= 0) {
                return;
            }
            if (options.rate() > 0) {
                generatedRecords += records;
                long targetNanos = startedAtNanos
                        + Math.round((generatedRecords * 1_000_000_000.0) / options.rate());
                sleepNanos(targetNanos - System.nanoTime());
                return;
            }
            sleepSeconds(options.delay());
        }
    }

    private record TextRecord(String line, String message) {}

    private record NetflowTarget(String host, int port, InetAddress address) {}

    private static void writeSuricataRecord(BufferedWriter writer, String target, RunOptions run, int recordIndex)
            throws IOException {
        TextRecord record = suricataRecord(target);
        writer.write(record.line());
        writer.newLine();
        flushIfNeeded(writer, run, recordIndex);
        if (!run.quiet()) {
            System.out.println(record.message());
        }
    }

    private static TextRecord suricataRecord(String target) {
        String[] protocols = {"TCP", "UDP", "ICMP"};
        String now = ISO_FMT.format(Instant.now());
        String proto = protocols[RNG.nextInt(protocols.length)];
        String srcIp = randomSourceIp();
        int srcPort = randInt(1024, 65535);
        String dstIp = randomDestinationIp();
        int dstPort = proto.equals("ICMP") ? 0 : randInt(1, 1024);

        StringBuilder sb = new StringBuilder(512);
        sb.append("{");
        jsonStr(sb, "timestamp", now);
        sb.append(",");
        jsonStr(sb, "event_type", "flow");
        sb.append(",");
        jsonStr(sb, "src_ip", srcIp);
        sb.append(",");
        jsonNum(sb, "src_port", srcPort);
        sb.append(",");
        jsonStr(sb, "dest_ip", dstIp);
        sb.append(",");
        jsonNum(sb, "dest_port", dstPort);
        sb.append(",");
        jsonStr(sb, "proto", proto);
        sb.append(",");
        jsonNum(sb, "flow_id", randInt(1_000_000, 9_999_999));
        sb.append(",");
        if (proto.equals("TCP")) {
            jsonStr(sb, "tcp_flags", "1b");
            sb.append(",");
        }
        sb.append("\"flow\":{");
        jsonNum(sb, "pkts_toserver", randInt(1, 100));
        sb.append(",");
        jsonNum(sb, "pkts_toclient", randInt(1, 100));
        sb.append(",");
        jsonNum(sb, "bytes_toserver", randInt(64, 15000));
        sb.append(",");
        jsonNum(sb, "bytes_toclient", randInt(64, 15000));
        sb.append(",");
        jsonStr(sb, "start", now);
        sb.append(",");
        jsonStr(sb, "end", now);
        sb.append(",");
        jsonNum(sb, "age", randInt(1, 60));
        sb.append(",");
        jsonStr(sb, "state", "established");
        sb.append(",");
        jsonStr(sb, "reason", "timeout");
        sb.append(",");
        sb.append("\"alerted\":false");
        sb.append("}}");

        String message = String.format(
                "Generated Suricata log: %s:%d -> %s:%d (%s) to %s",
                srcIp, srcPort, dstIp, dstPort, proto, target);
        return new TextRecord(sb.toString(), message);
    }

    private static void writeZeekRecord(BufferedWriter writer, String target, RunOptions run, int recordIndex)
            throws IOException {
        TextRecord record = zeekRecord(target);
        writer.write(record.line());
        writer.newLine();
        flushIfNeeded(writer, run, recordIndex);
        if (!run.quiet()) {
            System.out.println(record.message());
        }
    }

    private static TextRecord zeekRecord(String target) {
        String[] protocols = {"tcp", "udp", "icmp"};
        double ts = Instant.now().toEpochMilli() / 1000.0;
        String proto = protocols[RNG.nextInt(protocols.length)];
        String srcIp = randomSourceIp();
        int srcPort = randInt(1024, 65535);
        String dstIp = randomDestinationIp();
        int dstPort = proto.equals("icmp") ? 0 : randInt(1, 1024);
        double duration = Math.round(RNG.nextDouble() * 59.9 * 10000 + 1000) / 10000.0;

        StringBuilder sb = new StringBuilder(512);
        sb.append("{");
        jsonStr(sb, "_path", "conn");
        sb.append(",");
        jsonDouble(sb, "ts", ts);
        sb.append(",");
        jsonStr(sb, "uid", "C" + randLong(1_000_000_000L, 9_999_999_999L));
        sb.append(",");
        jsonStr(sb, "id.orig_h", srcIp);
        sb.append(",");
        jsonNum(sb, "id.orig_p", srcPort);
        sb.append(",");
        jsonStr(sb, "id.resp_h", dstIp);
        sb.append(",");
        jsonNum(sb, "id.resp_p", dstPort);
        sb.append(",");
        jsonStr(sb, "proto", proto);
        sb.append(",");
        jsonDouble(sb, "duration", duration);
        sb.append(",");
        jsonNum(sb, "orig_bytes", randInt(64, 15000));
        sb.append(",");
        jsonNum(sb, "resp_bytes", randInt(64, 15000));
        sb.append(",");
        jsonNum(sb, "orig_pkts", randInt(1, 100));
        sb.append(",");
        jsonNum(sb, "resp_pkts", randInt(1, 100));
        sb.append(",");
        jsonStr(sb, "conn_state", "SF");
        sb.append(",");
        jsonStr(sb, "history", "ShADadFf");
        sb.append(",");
        jsonNum(sb, "orig_ip_bytes", randInt(100, 16000));
        sb.append(",");
        jsonNum(sb, "resp_ip_bytes", randInt(100, 16000));
        sb.append("}");

        String message = String.format(
                "Generated Zeek conn log: %s:%d -> %s:%d (%s) to %s",
                srcIp, srcPort, dstIp, dstPort, proto, target);
        return new TextRecord(sb.toString(), message);
    }

    private static String restRecordJson(int sequence) {
        String now = ISO_FMT.format(Instant.now());
        String srcIp = randomSourceIp();
        String dstIp = randomDestinationIp();
        int samplingRate = samplingIntervalForSequence(sequence);
        int srcAsn = asnForIp(srcIp);
        int dstAsn = asnForIp(dstIp);
        StringBuilder sb = new StringBuilder(512);
        sb.append("{");
        jsonStr(sb, "sourceType", "rest");
        sb.append(",");
        jsonStr(sb, "exporterIp", "127.0.0.1");
        sb.append(",");
        jsonStr(sb, "receivedAt", now);
        sb.append(",");
        sb.append("\"fields\":{");
        jsonStr(sb, "src_ip", srcIp);
        sb.append(",");
        jsonStr(sb, "dst_ip", dstIp);
        sb.append(",");
        jsonNum(sb, "src_port", randInt(1024, 65535));
        sb.append(",");
        jsonNum(sb, "dst_port", 443);
        sb.append(",");
        jsonStr(sb, "protocol", "TCP");
        sb.append(",");
        jsonNum(sb, "bytes", randInt(100, 10000));
        sb.append(",");
        jsonNum(sb, "packets", randInt(1, 100));
        sb.append(",");
        jsonStr(sb, "ts_start", now);
        sb.append(",");
        jsonStr(sb, "ts_end", now);
        if (srcAsn > 0) {
            sb.append(",");
            jsonNum(sb, "src_asn", srcAsn);
        }
        if (dstAsn > 0) {
            sb.append(",");
            jsonNum(sb, "dst_asn", dstAsn);
        }
        if (samplingRate > 1) {
            sb.append(",");
            sb.append("\"sampled\":true");
            sb.append(",");
            jsonNum(sb, "sampling_rate", samplingRate);
            sb.append(",");
            jsonNum(sb, "sample_pool", Math.max(1, samplingRate * randInt(10, 100)));
        }
        sb.append("}}");
        return sb.toString();
    }

    private static void sendIngestBatch(URL url, String target, List<String> records, boolean quiet) {
        if (records.isEmpty()) {
            return;
        }
        String payload = records.size() == 1 ? records.getFirst() : "[" + String.join(",", records) + "]";
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(5_000);
            conn.setReadTimeout(30_000);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(payload.getBytes(StandardCharsets.UTF_8));
            }

            int status = conn.getResponseCode();
            if (!quiet) {
                System.out.printf("Sent REST API batch to %s records=%d status=%d%n", target, records.size(), status);
            }
        } catch (Exception e) {
            if (!quiet) {
                System.err.printf("Error sending REST API batch to %s records=%d: %s%n",
                        target, records.size(), e.getMessage());
            }
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private static void sendNetflowV5Packet(
            DatagramSocket sock,
            InetAddress addr,
            String host,
            int port,
            int flowSequence,
            int recordsInPacket,
            boolean quiet)
            throws IOException {
        long now = System.currentTimeMillis();
        int sysUptime = (int) (now & 0xFFFFFFFFL);
        int unixSecs = (int) (now / 1000);
        int unixNsecs = (int) ((now % 1000) * 1_000_000);

        ByteBuffer packet = ByteBuffer.allocate(24 + (recordsInPacket * 48));
        packet.putShort((short) 5);
        packet.putShort((short) recordsInPacket);
        packet.putInt(sysUptime);
        packet.putInt(unixSecs);
        packet.putInt(unixNsecs);
        packet.putInt(flowSequence);
        packet.put((byte) 0);
        packet.put((byte) 0);
        int samplingInterval = samplingIntervalForSequence(flowSequence);
        int samplingMode = samplingInterval > 1 ? 1 : 0;
        packet.putShort((short) ((samplingMode << 14) | samplingInterval));

        for (int recordIndex = 0; recordIndex < recordsInPacket; recordIndex++) {
            putNetflowV5Record(packet, sysUptime);
        }

        byte[] payload = packet.array();
        DatagramPacket dp = new DatagramPacket(payload, payload.length, addr, port);
        sock.send(dp);

        if (!quiet) {
            System.out.printf("Sent NetFlow v5 packet to %s:%d records=%d%n", host, port, recordsInPacket);
        }
    }

    private static void sendNetflowV9Packet(
            DatagramSocket sock, InetAddress addr, String host, int port, int flowSequence, boolean quiet)
            throws IOException {
        long now = System.currentTimeMillis();
        int sysUptime = (int) (now & 0xFFFFFFFFL);
        int unixSecs = (int) (now / 1000);
        int sourceId = 100;
        int dPkts = randInt(1, 1000);
        int dOctets = dPkts * randInt(64, 1500);
        int protocol = RNG.nextBoolean() ? 6 : 17;
        int dstPort = protocol == 6 ? 443 : 53;
        int tcpFlags = protocol == 6 ? 0x12 : 0;
        int[] srcIp = sourceIpv4Octets();
        int[] dstIp = destinationIpv4Octets();
        int samplingInterval = samplingIntervalForSequence(flowSequence);

        ByteBuffer packet = ByteBuffer.allocate(128);
        packet.putShort((short) 9);
        packet.putShort((short) 2);
        packet.putInt(sysUptime);
        packet.putInt(unixSecs);
        packet.putInt(flowSequence);
        packet.putInt(sourceId);

        packet.putShort((short) 0);
        packet.putShort((short) 60);
        packet.putShort((short) 256);
        packet.putShort((short) 13);
        putTemplateField(packet, 8, 4);
        putTemplateField(packet, 12, 4);
        putTemplateField(packet, 16, 4);
        putTemplateField(packet, 17, 4);
        putTemplateField(packet, 7, 2);
        putTemplateField(packet, 11, 2);
        putTemplateField(packet, 4, 1);
        putTemplateField(packet, 1, 4);
        putTemplateField(packet, 2, 4);
        putTemplateField(packet, 6, 1);
        putTemplateField(packet, 22, 4);
        putTemplateField(packet, 21, 4);
        putTemplateField(packet, 34, 4);

        packet.putShort((short) 256);
        packet.putShort((short) 48);
        putIpv4(packet, srcIp);
        putIpv4(packet, dstIp);
        packet.putInt(asnForOctets(srcIp));
        packet.putInt(asnForOctets(dstIp));
        packet.putShort((short) randInt(1024, 65535));
        packet.putShort((short) dstPort);
        packet.put((byte) protocol);
        packet.putInt(dOctets);
        packet.putInt(dPkts);
        packet.put((byte) tcpFlags);
        packet.putInt(sysUptime - 1000);
        packet.putInt(sysUptime);
        packet.putInt(samplingInterval);
        packet.putShort((short) 0);

        byte[] payload = packet.array();
        DatagramPacket dp = new DatagramPacket(payload, payload.length, addr, port);
        sock.send(dp);

        if (!quiet) {
            System.out.printf("Sent NetFlow v9 packet to %s:%d%n", host, port);
        }
    }

    private static NetflowTarget netflowTarget(String target) throws UnknownHostException {
        String[] parts = target.split(":");
        String host = parts[0];
        int port = parts.length > 1 ? Integer.parseInt(parts[1]) : 2055;
        return new NetflowTarget(host, port, InetAddress.getByName(host));
    }

    private static String httpTarget(String target) {
        return target.startsWith("http") ? target : "http://" + target;
    }

    private static String[] mixTypes(String option) {
        if (option == null || option.isBlank()) {
            return DEFAULT_MIX_TYPES;
        }
        Set<String> supported = Set.of(DEFAULT_MIX_TYPES);
        List<String> parsed = new ArrayList<>();
        for (String rawType : option.split(",")) {
            String type = rawType.trim().toLowerCase(Locale.ROOT);
            if (type.isEmpty()) {
                continue;
            }
            if (!supported.contains(type)) {
                throw new IllegalArgumentException("Unsupported mix source type: " + rawType.trim());
            }
            parsed.add(type);
        }
        if (parsed.isEmpty()) {
            throw new IllegalArgumentException("--mix-sources must include at least one source type");
        }
        return parsed.toArray(String[]::new);
    }

    private static String randomSourceIp() {
        return formatIpv4(sourceIpv4Octets());
    }

    private static String randomDestinationIp() {
        return formatIpv4(destinationIpv4Octets());
    }

    private static int[] sourceIpv4Octets() {
        int[][] prefixes = RNG.nextInt(3) == 0 ? ENRICHED_SOURCE_PREFIXES : PRIVATE_SOURCE_PREFIXES;
        return withHostOctet(prefixes[RNG.nextInt(prefixes.length)]);
    }

    private static int[] destinationIpv4Octets() {
        int[][] prefixes = RNG.nextInt(4) == 0 ? PRIVATE_DESTINATION_PREFIXES : ENRICHED_DESTINATION_PREFIXES;
        return withHostOctet(prefixes[RNG.nextInt(prefixes.length)]);
    }

    private static int[] withHostOctet(int[] prefix) {
        return new int[] {prefix[0], prefix[1], prefix[2], randInt(1, 254)};
    }

    private static String formatIpv4(int[] octets) {
        return octets[0] + "." + octets[1] + "." + octets[2] + "." + octets[3];
    }

    private static int samplingIntervalForSequence(int sequence) {
        if (Math.floorMod(sequence, 4) != 0) {
            return 1;
        }
        return SAMPLE_RATES[Math.floorMod(sequence / 4, SAMPLE_RATES.length)];
    }

    private static int asnForIp(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            return 0;
        }
        return asnForOctets(new int[] {
            Integer.parseInt(parts[0]),
            Integer.parseInt(parts[1]),
            Integer.parseInt(parts[2]),
            Integer.parseInt(parts[3])
        });
    }

    private static int asnForOctets(int[] octets) {
        if (octets[0] == 1 && octets[1] == 1 && octets[2] == 1) {
            return 13335;
        }
        if (octets[0] == 8 && octets[1] == 8 && octets[2] == 8) {
            return 15169;
        }
        if (octets[0] == 9 && octets[1] == 9 && octets[2] == 9) {
            return 19281;
        }
        if (octets[0] == 17) {
            return 714;
        }
        if (octets[0] == 93 && octets[1] == 184 && octets[2] == 216) {
            return 15133;
        }
        if (octets[0] == 104 && octets[1] >= 16 && octets[1] <= 31) {
            return 13335;
        }
        if (octets[0] == 142 && (octets[1] == 250 || octets[1] == 251)) {
            return 15169;
        }
        if (octets[0] == 208 && octets[1] == 67 && octets[2] == 222) {
            return 36692;
        }
        return 0;
    }

    private static void putNetflowV5Record(ByteBuffer packet, int sysUptime) {
        int[] srcIp = sourceIpv4Octets();
        int[] dstIp = destinationIpv4Octets();
        putIpv4(packet, srcIp);
        putIpv4(packet, dstIp);
        packet.putInt(0);                        // nexthop
        packet.putShort((short) 1);              // input
        packet.putShort((short) 2);              // output
        int dPkts = randInt(1, 1000);
        int dOctets = dPkts * randInt(64, 1500);
        packet.putInt(dPkts);
        packet.putInt(dOctets);
        packet.putInt(sysUptime - 1000);         // first
        packet.putInt(sysUptime);                // last
        packet.putShort((short) randInt(1024, 65535));
        packet.putShort((short) 80);
        packet.put((byte) 0);                    // pad1
        packet.put((byte) 0x12);                 // tcp flags
        packet.put((byte) 6);                    // protocol
        packet.put((byte) 0);                    // tos
        packet.putShort((short) asnForOctets(srcIp));
        packet.putShort((short) asnForOctets(dstIp));
        packet.put((byte) 24);                   // src_mask
        packet.put((byte) 24);                   // dst_mask
        packet.putShort((short) 0);              // pad2
    }

    private static void putIpv4(ByteBuffer packet, int[] octets) {
        putIpv4(packet, octets[0], octets[1], octets[2], octets[3]);
    }

    private static void putIpv4(ByteBuffer packet, int a, int b, int c, int d) {
        packet.put((byte) a);
        packet.put((byte) b);
        packet.put((byte) c);
        packet.put((byte) d);
    }

    private static void flushIfNeeded(BufferedWriter writer, RunOptions run, int recordIndex)
            throws IOException {
        if (!run.quiet() || recordIndex % 1_000 == 999) {
            writer.flush();
        }
    }

    /** Inclusive on both ends, matching Python's random.randint behaviour. */
    private static int randInt(int min, int max) {
        return RNG.nextInt(max - min + 1) + min;
    }

    private static long randLong(long min, long max) {
        return min + ((RNG.nextLong() & Long.MAX_VALUE) % (max - min + 1));
    }

    private static void putTemplateField(ByteBuffer packet, int type, int length) {
        packet.putShort((short) type);
        packet.putShort((short) length);
    }

    private static void sleepSeconds(double seconds) {
        if (seconds > 0) {
            sleepNanos(Math.round(seconds * 1_000_000_000.0));
        }
    }

    private static void sleepNanos(long nanos) {
        if (nanos <= 0) {
            return;
        }
        long deadline = System.nanoTime() + nanos;
        if (nanos > SPIN_SLEEP_THRESHOLD_NANOS) {
            long sleepNanos = nanos - SPIN_SLEEP_THRESHOLD_NANOS;
            try {
                Thread.sleep(sleepNanos / 1_000_000L, (int) (sleepNanos % 1_000_000L));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
        while (System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
    }

    // Minimal JSON helpers — avoids pulling in any JSON library
    private static void jsonStr(StringBuilder sb, String key, String value) {
        sb.append('"').append(key).append("\":\"").append(value).append('"');
    }

    private static void jsonNum(StringBuilder sb, String key, long value) {
        sb.append('"').append(key).append("\":").append(value);
    }

    private static void jsonDouble(StringBuilder sb, String key, double value) {
        sb.append('"').append(key).append("\":").append(value);
    }
}
