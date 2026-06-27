package com.kien.networkflowcollector.normalization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.kien.networkflowcollector.plugins.netflow.v5.NetFlowV5Normalizer;
import com.kien.networkflowcollector.plugins.netflow.v9.NetFlowV9Normalizer;
import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.spi.FlowNormalizer;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class FlowNormalizationServiceTest {

    private static final Set<String> NETFLOW_SOURCE_TYPES = Set.of("netflow-v5", "netflow-v9", "ipfix");

    private final FlowNormalizationService service =
            new FlowNormalizationService(
                    new NormalizerRegistry(
                            List.of(new NetFlowV5Normalizer(), new NetFlowV9Normalizer()),
                            NETFLOW_SOURCE_TYPES),
                    new NormalizedFlowValidator());

    @Test
    void routesNetFlowV5RecordThroughRegisteredNormalizer() {
        NormalizedFlow flow = service.normalize(netflowV5Raw());

        assertThat(flow.sourceType()).isEqualTo("netflow-v5");
        assertThat(flow.srcIp()).isEqualTo("10.0.0.1");
        assertThat(flow.dstIp()).isEqualTo("192.0.2.10");
        assertThat(flow.protocol()).isEqualTo("tcp");
        assertThat(flow.tcpFlags()).isEqualTo(27);
        assertThat(flow.sampled()).isFalse();
        assertThat(flow.samplingRate()).isNull();
        assertThat(flow.flowId()).isNotNull();
    }

    @Test
    void routesNetFlowV9RecordThroughRegisteredNormalizer() {
        NormalizedFlow flow = service.normalize(flexibleRaw("netflow-v9", 6, "tcp", 19));

        assertThat(flow.sourceType()).isEqualTo("netflow-v9");
        assertThat(flow.srcIp()).isEqualTo("10.0.0.3");
        assertThat(flow.dstIp()).isEqualTo("198.51.100.9");
        assertThat(flow.protocol()).isEqualTo("tcp");
        assertThat(flow.tcpFlags()).isEqualTo(19);
        assertThat(flow.durationMs()).isEqualTo(800);
    }

    @Test
    void routesIpfixRecordThroughRegisteredNormalizer() {
        NormalizedFlow flow = service.normalize(flexibleRaw("ipfix", 17, "udp", null));

        assertThat(flow.sourceType()).isEqualTo("ipfix");
        assertThat(flow.srcIp()).isEqualTo("10.0.0.3");
        assertThat(flow.dstIp()).isEqualTo("198.51.100.9");
        assertThat(flow.protocol()).isEqualTo("udp");
        assertThat(flow.tcpFlags()).isNull();
        assertThat(flow.durationMs()).isEqualTo(800);
    }

    @Test
    void loadsNetFlowNormalizersFromSpi() {
        NormalizerRegistry registry = NormalizerRegistry.fromServiceLoader(NETFLOW_SOURCE_TYPES);

        assertThat(registry.ready()).isTrue();
        assertThat(registry.sourceTypes()).contains("netflow-v5", "netflow-v9", "ipfix");
        assertThat(registry.coverage().missingSourceTypes()).isEmpty();
    }

    @Test
    void defaultRegistryUsesManifestCoverage() {
        NormalizerRegistry registry = new NormalizerRegistry();

        assertThat(registry.ready()).isTrue();
        assertThat(registry.coverage().requiredSourceTypes())
                .contains("netflow-v5", "netflow-v9", "ipfix");
        assertThat(registry.coverage().missingSourceTypes()).isEmpty();
    }

    @Test
    void duplicateSourceTypesFailFast() {
        FlowNormalizer duplicateNetFlowV5 = new StubNormalizer("netflow-v5");

        assertThatThrownBy(
                        () ->
                                new NormalizerRegistry(
                                        List.of(new NetFlowV5Normalizer(), duplicateNetFlowV5),
                                        Set.of("netflow-v5")))
                .isInstanceOf(NormalizerRegistryException.class)
                .hasMessageContaining("Duplicate normalizer");
    }

    @Test
    void missingCoverageKeepsServiceNotReady() {
        FlowNormalizationService incompleteService =
                new FlowNormalizationService(
                        new NormalizerRegistry(List.of(new NetFlowV5Normalizer()), NETFLOW_SOURCE_TYPES),
                        new NormalizedFlowValidator());

        assertThat(incompleteService.ready()).isFalse();
        assertThat(incompleteService.coverage().missingSourceTypes()).containsExactlyInAnyOrder("netflow-v9", "ipfix");
        assertThatThrownBy(() -> incompleteService.normalize(netflowV5Raw()))
                .isInstanceOf(NormalizationServiceNotReadyException.class)
                .hasMessageContaining("missing source types");
    }

    @Test
    void unsupportedRuntimeSourceTypeIsRejected() {
        RawFlowRecord raw =
                new RawFlowRecord(
                        "foreign-flow",
                        "198.51.100.7",
                        Instant.parse("2026-06-24T12:00:00Z"),
                        Map.of());

        assertThatThrownBy(() -> service.normalize(raw))
                .isInstanceOf(UnsupportedSourceTypeException.class)
                .hasMessageContaining("Unsupported source type");
    }

    @Test
    void invalidNormalizedFlowIsRejectedByCoreValidator() {
        RawFlowRecord raw = flexibleRaw("ipfix", 17, "udp", null, "not-an-ip");

        assertThatThrownBy(() -> service.normalize(raw))
                .isInstanceOf(FlowValidationException.class)
                .hasMessageContaining("srcIp must be an IP literal");
    }

    private static RawFlowRecord netflowV5Raw() {
        Instant tsStart = Instant.parse("2023-11-14T22:13:19.123Z");
        Instant tsEnd = Instant.parse("2023-11-14T22:13:19.623Z");
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("flow_sequence", 42L);
        fields.put("record_index", 0);
        fields.put("ts_start", tsStart);
        fields.put("ts_end", tsEnd);
        fields.put("duration_ms", 500L);
        fields.put("src_ip", "10.0.0.1");
        fields.put("src_port", 54_321);
        fields.put("dst_ip", "192.0.2.10");
        fields.put("dst_port", 443);
        fields.put("protocol_number", 6);
        fields.put("protocol", "tcp");
        fields.put("bytes", 3_456L);
        fields.put("packets", 12L);
        fields.put("tcp_flags", 27);
        fields.put("sampling_mode", 0);
        fields.put("sampling_interval", 0);
        return new RawFlowRecord(
                "netflow-v5",
                "198.51.100.7",
                Instant.parse("2026-06-24T12:00:00Z"),
                fields);
    }

    private static RawFlowRecord flexibleRaw(String sourceType, int protocolNumber, String protocol, Integer tcpFlags) {
        return flexibleRaw(sourceType, protocolNumber, protocol, tcpFlags, "10.0.0.3");
    }

    private static RawFlowRecord flexibleRaw(
            String sourceType, int protocolNumber, String protocol, Integer tcpFlags, String srcIp) {
        Instant tsStart = Instant.parse("2023-11-14T22:13:19Z");
        Instant tsEnd = Instant.parse("2023-11-14T22:13:19.800Z");
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("flow_sequence", 100L);
        fields.put("record_index", 0);
        fields.put("template_id", 256);
        fields.put("ts_start", tsStart);
        fields.put("ts_end", tsEnd);
        fields.put("duration_ms", 800L);
        fields.put("src_ip", srcIp);
        fields.put("src_port", 12_345);
        fields.put("dst_ip", "198.51.100.9");
        fields.put("dst_port", 443);
        fields.put("protocol_number", protocolNumber);
        fields.put("protocol", protocol);
        fields.put("bytes", 9_876L);
        fields.put("packets", 10L);
        if (tcpFlags != null) {
            fields.put("tcp_flags", tcpFlags);
        }
        return new RawFlowRecord(sourceType, "198.51.100.7", Instant.parse("2026-06-24T12:00:00Z"), fields);
    }

    private static final class StubNormalizer implements FlowNormalizer {

        private final String sourceType;

        private StubNormalizer(String sourceType) {
            this.sourceType = sourceType;
        }

        @Override
        public String sourceType() {
            return sourceType;
        }

        @Override
        public NormalizedFlow normalize(RawFlowRecord raw) {
            throw new UnsupportedOperationException("stub");
        }
    }
}
