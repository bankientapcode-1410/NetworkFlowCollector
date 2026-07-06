package com.kien.networkflowcollector.normalization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.enrichment.FlowEnrichmentProvider;
import com.kien.networkflowcollector.enrichment.IpEnrichment;
import com.kien.networkflowcollector.metrics.PipelineMetrics;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("FlowNormalizationService")
class FlowNormalizationServiceTest {

    private NormalizerRegistry registry;
    private NormalizedFlowValidator validator;
    private FlowNormalizationService service;

    private static final Instant NOW = Instant.now();

    @BeforeEach
    void setUp() {
        registry = mock(NormalizerRegistry.class);
        validator = mock(NormalizedFlowValidator.class);
        service = new FlowNormalizationService(registry, validator);
    }

    private RawFlowRecord rawRecord() {
        return new RawFlowRecord("netflow-v5", "10.0.0.1", NOW, Map.of("key", "val"));
    }

    @Test
    @DisplayName("Valid record → returns normalized flow")
    void normalize_validRecord_returnsNormalizedFlow() {
        NormalizedFlow expected = mock(NormalizedFlow.class);
        when(registry.ready()).thenReturn(true);
        when(registry.normalize(any())).thenReturn(expected);
        doNothing().when(validator).validate(any());

        NormalizedFlow result = service.normalize(rawRecord());

        assertThat(result).isSameAs(expected);
        verify(registry).normalize(any());
        verify(validator).validate(expected);
    }

    @Test
    @DisplayName("Valid record -> enriches before validation")
    void normalize_validRecord_enrichesBeforeValidation() {
        FlowEnrichmentProvider provider =
                ip -> switch (ip) {
                    case "8.8.8.8" -> Optional.of(new IpEnrichment("US", 15_169L, "Google LLC"));
                    case "93.184.216.34" -> Optional.of(new IpEnrichment("US", 15_133L, "Edgecast Inc"));
                    default -> Optional.empty();
                };
        service = new FlowNormalizationService(registry, validator, provider, PipelineMetrics.unregistered());
        NormalizedFlow base =
                new NormalizedFlow(
                        UUID.randomUUID(),
                        Instant.parse("2026-07-05T00:00:00Z"),
                        Instant.parse("2026-07-05T00:00:01Z"),
                        1_000,
                        "8.8.8.8",
                        53,
                        "93.184.216.34",
                        443,
                        "udp",
                        100,
                        2,
                        null,
                        false,
                        null,
                        null,
                        "rest",
                        "127.0.0.1",
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        NOW);
        when(registry.ready()).thenReturn(true);
        when(registry.normalize(any())).thenReturn(base);

        NormalizedFlow result = service.normalize(rawRecord());

        assertThat(result.srcCountryCode()).isEqualTo("US");
        assertThat(result.srcAsn()).isEqualTo(15_169L);
        assertThat(result.srcAsOrg()).isEqualTo("Google LLC");
        assertThat(result.dstCountryCode()).isEqualTo("US");
        assertThat(result.dstAsn()).isEqualTo(15_133L);
        assertThat(result.dstAsOrg()).isEqualTo("Edgecast Inc");
        verify(validator).validate(result);
    }

    @Test
    @DisplayName("Registry not ready → throws NormalizationServiceNotReadyException")
    void normalize_registryNotReady_throwsNotReadyException() {
        when(registry.ready()).thenReturn(false);
        NormalizerCoverage coverage = NormalizerCoverage.of(
                Set.of("netflow-v5", "netflow-v9"), Set.of("netflow-v5"));
        when(registry.coverage()).thenReturn(coverage);

        assertThatThrownBy(() -> service.normalize(rawRecord()))
                .isInstanceOf(NormalizationServiceNotReadyException.class);
    }

    @Test
    @DisplayName("Validation fails → FlowValidationException propagated")
    void normalize_validationFails_throwsValidationException() {
        when(registry.ready()).thenReturn(true);
        when(registry.normalize(any())).thenReturn(mock(NormalizedFlow.class));
        doThrow(new FlowValidationException("netflow-v5", "invalid_ip", "bad ip"))
                .when(validator).validate(any());

        assertThatThrownBy(() -> service.normalize(rawRecord()))
                .isInstanceOf(FlowValidationException.class);
    }

    @Test
    @DisplayName("Unsupported source type → exception propagated")
    void normalize_unsupportedSourceType_throwsException() {
        when(registry.ready()).thenReturn(true);
        when(registry.normalize(any())).thenThrow(new UnsupportedSourceTypeException("syslog"));

        assertThatThrownBy(() -> service.normalize(rawRecord()))
                .isInstanceOf(UnsupportedSourceTypeException.class);
    }

    @Test
    @DisplayName("normalizeAll → normalizes all records")
    void normalizeAll_multipleRecords_returnsAll() {
        NormalizedFlow flow = mock(NormalizedFlow.class);
        when(registry.ready()).thenReturn(true);
        when(registry.normalize(any())).thenReturn(flow);
        doNothing().when(validator).validate(any());

        List<RawFlowRecord> records = List.of(rawRecord(), rawRecord(), rawRecord());
        List<NormalizedFlow> results = service.normalizeAll(records);

        assertThat(results).hasSize(3);
    }

    @Test
    @DisplayName("ready() delegates to registry")
    void ready_delegatesToRegistry() {
        when(registry.ready()).thenReturn(true);
        assertThat(service.ready()).isTrue();

        when(registry.ready()).thenReturn(false);
        assertThat(service.ready()).isFalse();
    }

    @Test
    @DisplayName("coverage() delegates to registry")
    void coverage_delegatesToRegistry() {
        NormalizerCoverage coverage = NormalizerCoverage.of(
                Set.of("netflow-v5"), Set.of("netflow-v5"));
        when(registry.coverage()).thenReturn(coverage);

        assertThat(service.coverage()).isSameAs(coverage);
    }
}
