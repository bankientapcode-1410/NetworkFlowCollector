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
        boolean quiet = Boolean.parseBoolean(opts.getOrDefault("quiet", "false"));
        RunOptions run = new RunOptions(count, delay, rate, batchSize, quiet);

        String suricataTarget = opts.getOrDefault("suricata-target", "suricata-eve.json");
        String zeekTarget     = opts.getOrDefault("zeek-target", "conn.log");
        String netflowTarget  = opts.getOrDefault("netflow-target", "127.0.0.1:2055");
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
                generateMix(run, targets);
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
    }

    // ------------------------------------------------------------ Suricata

    private static void generateSuricataEve(String target, RunOptions run) throws Exception {
        String[] protocols = {"TCP", "UDP", "ICMP"};
        try (FileWriter fw = new FileWriter(target, true);
             BufferedWriter bw = new BufferedWriter(fw)) {
            Pacer pacer = new Pacer(run);
            for (int i = 0; i < run.count(); i++) {
                String now = ISO_FMT.format(Instant.now());
                String proto = protocols[RNG.nextInt(protocols.length)];
                String srcIp = "192.168.1." + randInt(1, 254);
                int srcPort = randInt(1024, 65535);
                String dstIp = "10.0.0." + randInt(1, 254);
                int dstPort = proto.equals("ICMP") ? 0 : randInt(1, 1024);

                StringBuilder sb = new StringBuilder(512);
                sb.append("{");
                jsonStr(sb, "timestamp", now);               sb.append(",");
                jsonStr(sb, "event_type", "flow");            sb.append(",");
                jsonStr(sb, "src_ip", srcIp);                 sb.append(",");
                jsonNum(sb, "src_port", srcPort);             sb.append(",");
                jsonStr(sb, "dest_ip", dstIp);                sb.append(",");
                jsonNum(sb, "dest_port", dstPort);            sb.append(",");
                jsonStr(sb, "proto", proto);                   sb.append(",");
                jsonNum(sb, "flow_id", randInt(1_000_000, 9_999_999));
                sb.append(",");

                // tcp_flags (only for TCP, placed before flow block like Python version)
                if (proto.equals("TCP")) {
                    jsonStr(sb, "tcp_flags", "1b"); sb.append(",");
                }

                sb.append("\"flow\":{");
                jsonNum(sb, "pkts_toserver", randInt(1, 100));  sb.append(",");
                jsonNum(sb, "pkts_toclient", randInt(1, 100));  sb.append(",");
                jsonNum(sb, "bytes_toserver", randInt(64, 15000)); sb.append(",");
                jsonNum(sb, "bytes_toclient", randInt(64, 15000)); sb.append(",");
                jsonStr(sb, "start", now);                    sb.append(",");
                jsonStr(sb, "end", now);                      sb.append(",");
                jsonNum(sb, "age", randInt(1, 60));           sb.append(",");
                jsonStr(sb, "state", "established");          sb.append(",");
                jsonStr(sb, "reason", "timeout");             sb.append(",");
                sb.append("\"alerted\":false");
                sb.append("}}");

                bw.write(sb.toString());
                bw.newLine();
                flushIfNeeded(bw, run, i);

                if (!run.quiet()) {
                    System.out.printf("Generated Suricata log: %s:%d -> %s:%d (%s) to %s%n",
                            srcIp, srcPort, dstIp, dstPort, proto, target);
                }

                pacer.afterRecords(1);
            }
        }
    }

    // --------------------------------------------------------------- Zeek

    private static void generateZeekConn(String target, RunOptions run) throws Exception {
        String[] protocols = {"tcp", "udp", "icmp"};
        try (FileWriter fw = new FileWriter(target, true);
             BufferedWriter bw = new BufferedWriter(fw)) {
            Pacer pacer = new Pacer(run);
            for (int i = 0; i < run.count(); i++) {
                double ts = Instant.now().toEpochMilli() / 1000.0;
                String proto = protocols[RNG.nextInt(protocols.length)];
                String srcIp = "192.168.1." + randInt(1, 254);
                int srcPort = randInt(1024, 65535);
                String dstIp = "10.0.0." + randInt(1, 254);
                int dstPort = proto.equals("icmp") ? 0 : randInt(1, 1024);
                double duration = Math.round(RNG.nextDouble() * 59.9 * 10000 + 1000) / 10000.0;

                StringBuilder sb = new StringBuilder(512);
                sb.append("{");
                jsonStr(sb, "_path", "conn");                 sb.append(",");
                jsonDouble(sb, "ts", ts);                     sb.append(",");
                jsonStr(sb, "uid", "C" + randLong(1_000_000_000L, 9_999_999_999L)); sb.append(",");
                jsonStr(sb, "id.orig_h", srcIp);              sb.append(",");
                jsonNum(sb, "id.orig_p", srcPort);            sb.append(",");
                jsonStr(sb, "id.resp_h", dstIp);              sb.append(",");
                jsonNum(sb, "id.resp_p", dstPort);            sb.append(",");
                jsonStr(sb, "proto", proto);                   sb.append(",");
                jsonDouble(sb, "duration", duration);          sb.append(",");
                jsonNum(sb, "orig_bytes", randInt(64, 15000)); sb.append(",");
                jsonNum(sb, "resp_bytes", randInt(64, 15000)); sb.append(",");
                jsonNum(sb, "orig_pkts", randInt(1, 100));    sb.append(",");
                jsonNum(sb, "resp_pkts", randInt(1, 100));    sb.append(",");
                jsonStr(sb, "conn_state", "SF");              sb.append(",");
                jsonStr(sb, "history", "ShADadFf");           sb.append(",");
                jsonNum(sb, "orig_ip_bytes", randInt(100, 16000)); sb.append(",");
                jsonNum(sb, "resp_ip_bytes", randInt(100, 16000));
                sb.append("}");

                bw.write(sb.toString());
                bw.newLine();
                flushIfNeeded(bw, run, i);

                if (!run.quiet()) {
                    System.out.printf("Generated Zeek conn log: %s:%d -> %s:%d (%s) to %s%n",
                            srcIp, srcPort, dstIp, dstPort, proto, target);
                }

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
                long now = System.currentTimeMillis();
                int sysUptime = (int) (now & 0xFFFFFFFFL);
                int unixSecs  = (int) (now / 1000);
                int unixNsecs = (int) ((now % 1000) * 1_000_000);

                ByteBuffer packet = ByteBuffer.allocate(24 + (recordsInPacket * 48));
                packet.putShort((short) 5);              // version
                packet.putShort((short) recordsInPacket);// flow count
                packet.putInt(sysUptime);
                packet.putInt(unixSecs);
                packet.putInt(unixNsecs);
                packet.putInt(sentRecords);              // flow sequence
                packet.put((byte) 0);                    // engine type
                packet.put((byte) 0);                    // engine id
                packet.putShort((short) 0);              // sampling interval

                for (int recordIndex = 0; recordIndex < recordsInPacket; recordIndex++) {
                    putNetflowV5Record(packet, sysUptime);
                }

                byte[] payload = packet.array();

                DatagramPacket dp = new DatagramPacket(payload, payload.length, addr, port);
                sock.send(dp);

                if (!run.quiet()) {
                    System.out.printf(
                            "Sent NetFlow v5 packet to %s:%d records=%d%n",
                            host,
                            port,
                            recordsInPacket);
                }

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
                long now = System.currentTimeMillis();
                int sysUptime = (int) (now & 0xFFFFFFFFL);
                int unixSecs = (int) (now / 1000);
                int flowSequence = i;
                int sourceId = 100;

                byte[] srcAddr = InetAddress.getByName("192.168.1." + randInt(1, 254)).getAddress();
                byte[] dstAddr = InetAddress.getByName("10.0.0." + randInt(1, 254)).getAddress();
                int dPkts = randInt(1, 1000);
                int dOctets = dPkts * randInt(64, 1500);
                int protocol = RNG.nextBoolean() ? 6 : 17;
                int dstPort = protocol == 6 ? 443 : 53;
                int tcpFlags = protocol == 6 ? 0x12 : 0;

                ByteBuffer packet = ByteBuffer.allocate(104);

                packet.putShort((short) 9);              // version
                packet.putShort((short) 2);              // template record + data record
                packet.putInt(sysUptime);
                packet.putInt(unixSecs);
                packet.putInt(flowSequence);
                packet.putInt(sourceId);

                packet.putShort((short) 0);              // template FlowSet id
                packet.putShort((short) 48);             // FlowSet header + template header + fields
                packet.putShort((short) 256);            // template id
                packet.putShort((short) 10);             // field count
                putTemplateField(packet, 8, 4);          // src_ip
                putTemplateField(packet, 12, 4);         // dst_ip
                putTemplateField(packet, 7, 2);          // src_port
                putTemplateField(packet, 11, 2);         // dst_port
                putTemplateField(packet, 4, 1);          // protocol
                putTemplateField(packet, 1, 4);          // bytes
                putTemplateField(packet, 2, 4);          // packets
                putTemplateField(packet, 6, 1);          // tcp_flags
                putTemplateField(packet, 22, 4);         // first_switched
                putTemplateField(packet, 21, 4);         // last_switched

                packet.putShort((short) 256);            // data FlowSet id = template id
                packet.putShort((short) 36);             // FlowSet header + record + two bytes padding
                packet.put(srcAddr);
                packet.put(dstAddr);
                packet.putShort((short) randInt(1024, 65535));
                packet.putShort((short) dstPort);
                packet.put((byte) protocol);
                packet.putInt(dOctets);
                packet.putInt(dPkts);
                packet.put((byte) tcpFlags);
                packet.putInt(sysUptime - 1000);
                packet.putInt(sysUptime);
                packet.putShort((short) 0);              // 2-byte FlowSet padding

                byte[] payload = packet.array();
                DatagramPacket dp = new DatagramPacket(payload, payload.length, addr, port);
                sock.send(dp);

                if (!run.quiet()) {
                    System.out.printf("Sent NetFlow v9 packet to %s:%d%n", host, port);
                }

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
        for (int i = 0; i < run.count(); i++) {
            String now = ISO_FMT.format(Instant.now());

            StringBuilder sb = new StringBuilder(512);
            sb.append("{");
            jsonStr(sb, "sourceType", "rest");               sb.append(",");
            jsonStr(sb, "exporterIp", "127.0.0.1");          sb.append(",");
            jsonStr(sb, "receivedAt", now);                   sb.append(",");
            sb.append("\"fields\":{");
            jsonStr(sb, "src_ip", "192.168.2." + randInt(1, 254)); sb.append(",");
            jsonStr(sb, "dst_ip", "10.1.0." + randInt(1, 254));   sb.append(",");
            jsonNum(sb, "src_port", randInt(1024, 65535));         sb.append(",");
            jsonNum(sb, "dst_port", 443);                          sb.append(",");
            jsonStr(sb, "protocol", "TCP");                        sb.append(",");
            jsonNum(sb, "bytes", randInt(100, 10000));             sb.append(",");
            jsonNum(sb, "packets", randInt(1, 100));               sb.append(",");
            jsonStr(sb, "ts_start", now);                          sb.append(",");
            jsonStr(sb, "ts_end", now);
            sb.append("}}");

            String json = sb.toString();

            try {
                URL url = new URL(target);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setDoOutput(true);

                try (OutputStream os = conn.getOutputStream()) {
                    os.write(json.getBytes(StandardCharsets.UTF_8));
                }

                int status = conn.getResponseCode();
                if (!run.quiet()) {
                    System.out.printf("Sent REST API record to %s, status: %d%n", target, status);
                }
                conn.disconnect();
            } catch (Exception e) {
                if (!run.quiet()) {
                    System.err.printf("Error sending REST API record to %s: %s%n", target, e.getMessage());
                }
            }

            pacer.afterRecords(1);
        }
    }

    // ----------------------------------------------------------------- Mix

    private static void generateMix(RunOptions run, Map<String, String> targets) throws Exception {
        String[] types = {"suricata", "zeek", "netflow-v5", "netflow-v9", "ingest"};
        List<String> initialTypes = new ArrayList<>(Arrays.asList(types));
        Collections.shuffle(initialTypes, RNG);
        Pacer pacer = new Pacer(run);
        RunOptions single = run.withCountAndNoPacing(1);
        for (int i = 0; i < run.count(); i++) {
            String t = i < initialTypes.size() ? initialTypes.get(i) : types[RNG.nextInt(types.length)];
            switch (t) {
                case "suricata":   generateSuricataEve(targets.get("suricata"), single); break;
                case "zeek":       generateZeekConn(targets.get("zeek"), single);        break;
                case "netflow-v5": sendNetflowV5(targets.get("netflow"), single);        break;
                case "netflow-v9": sendNetflowV9(targets.get("netflow"), single);        break;
                case "ingest":     sendIngestApi(targets.get("ingest"), single);         break;
            }
            pacer.afterRecords(1);
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

        private RunOptions withCountAndNoPacing(int newCount) {
            return new RunOptions(newCount, 0, 0, batchSize, quiet);
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

    private static void putNetflowV5Record(ByteBuffer packet, int sysUptime) {
        putIpv4(packet, 192, 168, 1, randInt(1, 254));
        putIpv4(packet, 10, 0, 0, randInt(1, 254));
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
        packet.putShort((short) 0);              // src_as
        packet.putShort((short) 0);              // dst_as
        packet.put((byte) 24);                   // src_mask
        packet.put((byte) 24);                   // dst_mask
        packet.putShort((short) 0);              // pad2
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
        if (nanos > 0) {
            try {
                Thread.sleep(nanos / 1_000_000L, (int) (nanos % 1_000_000L));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
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
