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

        String suricataTarget = opts.getOrDefault("suricata-target", "suricata-eve.json");
        String zeekTarget     = opts.getOrDefault("zeek-target", "conn.log");
        String netflowTarget  = opts.getOrDefault("netflow-target", "127.0.0.1:2055");
        String ingestTarget   = opts.getOrDefault("ingest-target", "http://127.0.0.1:8080/ingest");

        switch (type) {
            case "suricata":
                generateSuricataEve(opts.getOrDefault("target", suricataTarget), count, delay);
                break;
            case "zeek":
                generateZeekConn(opts.getOrDefault("target", zeekTarget), count, delay);
                break;
            case "netflow":
                sendNetflow(
                        opts.getOrDefault("target", netflowTarget),
                        opts.getOrDefault("netflow-version", opts.getOrDefault("version", "5")),
                        count,
                        delay);
                break;
            case "netflow-v5":
                sendNetflowV5(opts.getOrDefault("target", netflowTarget), count, delay);
                break;
            case "netflow-v9":
                sendNetflowV9(opts.getOrDefault("target", netflowTarget), count, delay);
                break;
            case "ingest":
                sendIngestApi(opts.getOrDefault("target", ingestTarget), count, delay);
                break;
            case "mix":
                Map<String, String> targets = new HashMap<>();
                targets.put("suricata", suricataTarget);
                targets.put("zeek", zeekTarget);
                targets.put("netflow", netflowTarget);
                targets.put("ingest", ingestTarget);
                generateMix(count, delay, targets);
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
            if (arg.startsWith("--")) {
                String key = arg.substring(2);
                if (i + 1 < args.length && !args[i + 1].startsWith("-")) {
                    opts.put(key, args[++i]);
                }
            } else if (arg.equals("-t") && i + 1 < args.length) {
                opts.put("target", args[++i]);
            } else if (arg.equals("-c") && i + 1 < args.length) {
                opts.put("count", args[++i]);
            } else if (arg.equals("-d") && i + 1 < args.length) {
                opts.put("delay", args[++i]);
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
        System.out.println("  --suricata-target <file>       Suricata EVE output file (default: suricata-eve.json)");
        System.out.println("  --zeek-target <file>           Zeek conn log output file (default: conn.log)");
        System.out.println("  --netflow-target <host:port>   NetFlow v5/v9 UDP target (default: 127.0.0.1:2055)");
        System.out.println("  --netflow-version <5|9>        Version for type netflow (default: 5)");
        System.out.println("  --ingest-target <url>          REST ingest API URL (default: http://127.0.0.1:8080/ingest)");
    }

    // ------------------------------------------------------------ Suricata

    private static void generateSuricataEve(String target, int count, double delay) throws Exception {
        String[] protocols = {"TCP", "UDP", "ICMP"};
        try (FileWriter fw = new FileWriter(target, true);
             BufferedWriter bw = new BufferedWriter(fw)) {
            for (int i = 0; i < count; i++) {
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
                bw.flush();

                System.out.printf("Generated Suricata log: %s:%d -> %s:%d (%s) to %s%n",
                        srcIp, srcPort, dstIp, dstPort, proto, target);

                sleepSeconds(delay);
            }
        }
    }

    // --------------------------------------------------------------- Zeek

    private static void generateZeekConn(String target, int count, double delay) throws Exception {
        String[] protocols = {"tcp", "udp", "icmp"};
        try (FileWriter fw = new FileWriter(target, true);
             BufferedWriter bw = new BufferedWriter(fw)) {
            for (int i = 0; i < count; i++) {
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
                bw.flush();

                System.out.printf("Generated Zeek conn log: %s:%d -> %s:%d (%s) to %s%n",
                        srcIp, srcPort, dstIp, dstPort, proto, target);

                sleepSeconds(delay);
            }
        }
    }

    // ----------------------------------------------------------- NetFlow v5

    private static void sendNetflow(String target, String version, int count, double delay) throws Exception {
        if ("9".equals(version) || "v9".equalsIgnoreCase(version) || "netflow-v9".equalsIgnoreCase(version)) {
            sendNetflowV9(target, count, delay);
        } else if ("5".equals(version) || "v5".equalsIgnoreCase(version) || "netflow-v5".equalsIgnoreCase(version)) {
            sendNetflowV5(target, count, delay);
        } else {
            throw new IllegalArgumentException("Unsupported NetFlow generator version: " + version);
        }
    }

    private static void sendNetflowV5(String target, int count, double delay) throws Exception {
        String[] parts = target.split(":");
        String host = parts[0];
        int port = parts.length > 1 ? Integer.parseInt(parts[1]) : 2055;

        try (DatagramSocket sock = new DatagramSocket()) {
            InetAddress addr = InetAddress.getByName(host);

            for (int i = 0; i < count; i++) {
                long now = System.currentTimeMillis();
                int sysUptime = (int) (now & 0xFFFFFFFFL);
                int unixSecs  = (int) (now / 1000);
                int unixNsecs = (int) ((now % 1000) * 1_000_000);

                // Header: 24 bytes
                ByteBuffer header = ByteBuffer.allocate(24);
                header.putShort((short) 5);              // version
                header.putShort((short) 1);              // flow count
                header.putInt(sysUptime);
                header.putInt(unixSecs);
                header.putInt(unixNsecs);
                header.putInt(i);                        // flow sequence
                header.put((byte) 0);                    // engine type
                header.put((byte) 0);                    // engine id
                header.putShort((short) 0);              // sampling interval

                // Record: 48 bytes
                byte[] srcAddr = InetAddress.getByName("192.168.1." + randInt(1, 254)).getAddress();
                byte[] dstAddr = InetAddress.getByName("10.0.0." + randInt(1, 254)).getAddress();
                int dPkts   = randInt(1, 1000);
                int dOctets = dPkts * randInt(64, 1500);

                ByteBuffer record = ByteBuffer.allocate(48);
                record.put(srcAddr);                     // src addr  (4)
                record.put(dstAddr);                     // dst addr  (4)
                record.putInt(0);                        // nexthop   (4)
                record.putShort((short) 1);              // input     (2)
                record.putShort((short) 2);              // output    (2)
                record.putInt(dPkts);                    // dPkts     (4)
                record.putInt(dOctets);                  // dOctets   (4)
                record.putInt(sysUptime - 1000);         // first     (4)
                record.putInt(sysUptime);                // last      (4)
                record.putShort((short) randInt(1024, 65535)); // srcport (2)
                record.putShort((short) 80);             // dstport   (2)
                record.put((byte) 0);                    // pad1      (1)
                record.put((byte) 0x12);                 // tcp flags (1)
                record.put((byte) 6);                    // protocol  (1)
                record.put((byte) 0);                    // tos       (1)
                record.putShort((short) 0);              // src_as    (2)
                record.putShort((short) 0);              // dst_as    (2)
                record.put((byte) 24);                   // src_mask  (1)
                record.put((byte) 24);                   // dst_mask  (1)
                record.putShort((short) 0);              // pad2      (2)

                byte[] packet = new byte[72];
                System.arraycopy(header.array(), 0, packet, 0, 24);
                System.arraycopy(record.array(), 0, packet, 24, 48);

                DatagramPacket dp = new DatagramPacket(packet, packet.length, addr, port);
                sock.send(dp);

                System.out.printf("Sent NetFlow v5 packet to %s:%d%n", host, port);

                sleepSeconds(delay);
            }
        }
    }

    // ----------------------------------------------------------- NetFlow v9

    private static void sendNetflowV9(String target, int count, double delay) throws Exception {
        String[] parts = target.split(":");
        String host = parts[0];
        int port = parts.length > 1 ? Integer.parseInt(parts[1]) : 2055;

        try (DatagramSocket sock = new DatagramSocket()) {
            InetAddress addr = InetAddress.getByName(host);

            for (int i = 0; i < count; i++) {
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

                System.out.printf("Sent NetFlow v9 packet to %s:%d%n", host, port);

                sleepSeconds(delay);
            }
        }
    }

    // --------------------------------------------------------- REST Ingest

    private static void sendIngestApi(String target, int count, double delay) throws Exception {
        if (!target.startsWith("http")) {
            target = "http://" + target;
        }

        for (int i = 0; i < count; i++) {
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
                System.out.printf("Sent REST API record to %s, status: %d%n", target, status);
                conn.disconnect();
            } catch (Exception e) {
                System.err.printf("Error sending REST API record to %s: %s%n", target, e.getMessage());
            }

            sleepSeconds(delay);
        }
    }

    // ----------------------------------------------------------------- Mix

    private static void generateMix(int count, double delay, Map<String, String> targets) throws Exception {
        String[] types = {"suricata", "zeek", "netflow-v5", "netflow-v9", "ingest"};
        List<String> initialTypes = new ArrayList<>(Arrays.asList(types));
        Collections.shuffle(initialTypes, RNG);
        for (int i = 0; i < count; i++) {
            String t = i < initialTypes.size() ? initialTypes.get(i) : types[RNG.nextInt(types.length)];
            switch (t) {
                case "suricata":   generateSuricataEve(targets.get("suricata"), 1, 0); break;
                case "zeek":       generateZeekConn(targets.get("zeek"), 1, 0);        break;
                case "netflow-v5": sendNetflowV5(targets.get("netflow"), 1, 0);        break;
                case "netflow-v9": sendNetflowV9(targets.get("netflow"), 1, 0);        break;
                case "ingest":     sendIngestApi(targets.get("ingest"), 1, 0);         break;
            }
            sleepSeconds(delay);
        }
    }

    // ------------------------------------------------------------ Helpers

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
            try {
                Thread.sleep((long) (seconds * 1000));
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
