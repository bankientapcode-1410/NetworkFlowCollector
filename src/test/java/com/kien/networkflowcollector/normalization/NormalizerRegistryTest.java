package com.kien.networkflowcollector.normalization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.kien.networkflowcollector.common.NormalizedFlow;
import com.kien.networkflowcollector.spi.FlowNormalizer;
import com.kien.networkflowcollector.spi.RawFlowRecord;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("NormalizerRegistry")
class NormalizerRegistryTest {

    private static final Instant NOW = Instant.now();

    private FlowNormalizer mockNormalizer(String sourceType) {
        FlowNormalizer n = mock(FlowNormalizer.class);
        when(n.sourceType()).thenReturn(sourceType);
        return n;
    }

    private RawFlowRecord rawRecord(String sourceType) {
        return new RawFlowRecord(sourceType, "10.0.0.1", NOW, Map.of("key", "val"));
    }

    @Test
    @DisplayName("Known source type → delegates to correct normalizer")
    void normalize_knownSourceType_delegates() {
        FlowNormalizer v5 = mockNormalizer("netflow-v5");
        NormalizedFlow expected = mock(NormalizedFlow.class);
        RawFlowRecord raw = rawRecord("netflow-v5");
        when(v5.normalize(raw)).thenReturn(expected);

        NormalizerRegistry registry = new NormalizerRegistry(List.of(v5), Set.of("netflow-v5"));
        NormalizedFlow result = registry.normalize(raw);

        assertThat(result).isSameAs(expected);
        verify(v5).normalize(raw);
    }

    @Test
    @DisplayName("Unknown source type → throws UnsupportedSourceTypeException")
    void normalize_unknownSourceType_throwsUnsupported() {
        FlowNormalizer v5 = mockNormalizer("netflow-v5");
        NormalizerRegistry registry = new NormalizerRegistry(List.of(v5), Set.of("netflow-v5"));

        assertThatThrownBy(() -> registry.normalize(rawRecord("syslog")))
                .isInstanceOf(UnsupportedSourceTypeException.class)
                .hasMessageContaining("syslog");
    }

    @Test
    @DisplayName("Duplicate source type → throws NormalizerRegistryException")
    void duplicateSourceType_throwsRegistryException() {
        FlowNormalizer a = mockNormalizer("netflow-v5");
        FlowNormalizer b = mockNormalizer("netflow-v5");

        assertThatThrownBy(() -> new NormalizerRegistry(List.of(a, b), Set.of("netflow-v5")))
                .isInstanceOf(NormalizerRegistryException.class)
                .hasMessageContaining("Duplicate");
    }

    @Test
    @DisplayName("Blank source type → throws NormalizerRegistryException")
    void blankSourceType_throwsRegistryException() {
        FlowNormalizer blank = mockNormalizer("  ");

        assertThatThrownBy(() -> new NormalizerRegistry(List.of(blank), Set.of()))
                .isInstanceOf(NormalizerRegistryException.class)
                .hasMessageContaining("blank");
    }

    @Test
    @DisplayName("All required types covered → ready = true")
    void ready_allCovered_returnsTrue() {
        FlowNormalizer v5 = mockNormalizer("netflow-v5");
        NormalizerRegistry registry = new NormalizerRegistry(List.of(v5), Set.of("netflow-v5"));

        assertThat(registry.ready()).isTrue();
    }

    @Test
    @DisplayName("Missing required type → ready = false")
    void ready_missingType_returnsFalse() {
        FlowNormalizer v5 = mockNormalizer("netflow-v5");
        NormalizerRegistry registry = new NormalizerRegistry(
                List.of(v5), Set.of("netflow-v5", "netflow-v9"));

        assertThat(registry.ready()).isFalse();
    }

    @Test
    @DisplayName("Coverage reports missing source types")
    void coverage_reportsMissingTypes() {
        FlowNormalizer v5 = mockNormalizer("netflow-v5");
        NormalizerRegistry registry = new NormalizerRegistry(
                List.of(v5), Set.of("netflow-v5", "netflow-v9"));

        NormalizerCoverage coverage = registry.coverage();

        assertThat(coverage.missingSourceTypes()).containsExactly("netflow-v9");
        assertThat(coverage.complete()).isFalse();
    }

    @Test
    @DisplayName("sourceTypes returns all registered types")
    void sourceTypes_returnsRegisteredTypes() {
        FlowNormalizer v5 = mockNormalizer("netflow-v5");
        FlowNormalizer v9 = mockNormalizer("netflow-v9");
        NormalizerRegistry registry = new NormalizerRegistry(
                List.of(v5, v9), Set.of("netflow-v5", "netflow-v9"));

        assertThat(registry.sourceTypes()).containsExactlyInAnyOrder("netflow-v5", "netflow-v9");
    }
}
