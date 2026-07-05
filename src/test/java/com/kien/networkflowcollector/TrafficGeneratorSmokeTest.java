package com.kien.networkflowcollector;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.CleanupMode;
import org.junit.jupiter.api.io.TempDir;

class TrafficGeneratorSmokeTest {

    @TempDir(cleanup = CleanupMode.NEVER)
    private Path tempDir;

    @Test
    void writesSuricataAndZeekFiles() throws Exception {
        Path suricataLog = tempDir.resolve("suricata-eve.json");
        Path zeekLog = tempDir.resolve("conn.log");

        TrafficGenerator.main(
                new String[] {"suricata", "-t", suricataLog.toString(), "-c", "3", "-d", "0"});
        TrafficGenerator.main(new String[] {"zeek", "-t", zeekLog.toString(), "-c", "3", "-d", "0"});

        List<String> suricataLines = Files.readAllLines(suricataLog);
        List<String> zeekLines = Files.readAllLines(zeekLog);

        assertThat(suricataLines).hasSize(3).allSatisfy(line -> assertThat(line).contains("\"event_type\":\"flow\""));
        assertThat(zeekLines).hasSize(3).allSatisfy(line -> assertThat(line).contains("\"_path\":\"conn\""));
    }

    @Test
    void sendsNetFlowV5PacketsOverUdp() throws Exception {
        try (DatagramSocket receiver = new DatagramSocket(0, InetAddress.getByName("127.0.0.1"))) {
            receiver.setSoTimeout(2_000);
            int port = receiver.getLocalPort();

            TrafficGenerator.main(new String[] {"netflow", "-t", "127.0.0.1:" + port, "-c", "2", "-d", "0"});

            for (int index = 0; index < 2; index++) {
                byte[] buffer = new byte[1500];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                receiver.receive(packet);

                assertThat(packet.getLength()).isEqualTo(72);
                assertThat(ByteBuffer.wrap(packet.getData(), 0, packet.getLength())
                                .order(ByteOrder.BIG_ENDIAN)
                                .getShort())
                        .isEqualTo((short) 5);
            }
        }
    }

    @Test
    void sendsNetFlowV9PacketsOverUdp() throws Exception {
        try (DatagramSocket receiver = new DatagramSocket(0, InetAddress.getByName("127.0.0.1"))) {
            receiver.setSoTimeout(2_000);
            int port = receiver.getLocalPort();

            TrafficGenerator.main(new String[] {"netflow-v9", "-t", "127.0.0.1:" + port, "-c", "2", "-d", "0"});

            for (int index = 0; index < 2; index++) {
                byte[] buffer = new byte[1500];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                receiver.receive(packet);

                assertThat(packet.getLength()).isEqualTo(104);
                assertThat(ByteBuffer.wrap(packet.getData(), 0, packet.getLength())
                                .order(ByteOrder.BIG_ENDIAN)
                                .getShort())
                        .isEqualTo((short) 9);
            }
        }
    }

    @Test
    void mixSendsNetFlowV5AndV9PacketsOverUdp() throws Exception {
        Path suricataLog = tempDir.resolve("mix-suricata-eve.json");
        Path zeekLog = tempDir.resolve("mix-conn.log");

        try (DatagramSocket receiver = new DatagramSocket(0, InetAddress.getByName("127.0.0.1"))) {
            receiver.setSoTimeout(2_000);
            int port = receiver.getLocalPort();

            TrafficGenerator.main(
                    new String[] {
                        "mix",
                        "--suricata-target", suricataLog.toString(),
                        "--zeek-target", zeekLog.toString(),
                        "--netflow-target", "127.0.0.1:" + port,
                        "--ingest-target", "http://127.0.0.1:1/ingest",
                        "-c", "5",
                        "-d", "0"
                    });

            Set<Short> versions = new HashSet<>();
            for (int index = 0; index < 2; index++) {
                byte[] buffer = new byte[1500];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                receiver.receive(packet);

                versions.add(
                        ByteBuffer.wrap(packet.getData(), 0, packet.getLength())
                                .order(ByteOrder.BIG_ENDIAN)
                                .getShort());
            }

            assertThat(versions).containsExactlyInAnyOrder((short) 5, (short) 9);
        }
    }
}
