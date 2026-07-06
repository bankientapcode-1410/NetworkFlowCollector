package com.kien.networkflowcollector.normalization;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.kien.networkflowcollector.common.NormalizedFlow;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("NormalizedFlowValidator")
class NormalizedFlowValidatorTest {

    private static final Instant TS_START = Instant.parse("2026-06-19T08:15:30Z");
    private static final Instant TS_END   = Instant.parse("2026-06-19T08:15:35Z");
    private static final long DURATION_MS = 5000L;

    private NormalizedFlowValidator validator;

    @BeforeEach
    void setUp() {
        validator = new NormalizedFlowValidator();
    }

    /** Returns a fully valid NormalizedFlow (TCP, unsampled). */
    private NormalizedFlow validFlow() {
        return new NormalizedFlow(
                UUID.randomUUID(), TS_START, TS_END, DURATION_MS,
                "10.20.30.40", 54321, "93.184.216.34", 443,
                "tcp", 18432L, 24L, 0x1b,
                false, null, null,
                "netflow-v5", "10.0.0.1",
                null, null, null, null, null, null,
                Instant.now());
    }

    @Test
    @DisplayName("Valid flow → no exception")
    void validate_validFlow_noException() {
        assertThatCode(() -> validator.validate(validFlow()))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("Missing flowId → FlowValidationException(missing_field)")
    void validate_missingFlowId_throwsException() {
        NormalizedFlow flow = new NormalizedFlow(
                null, TS_START, TS_END, DURATION_MS,
                "10.20.30.40", 54321, "93.184.216.34", 443,
                "tcp", 18432L, 24L, 0x1b,
                false, null, null,
                "netflow-v5", "10.0.0.1",
                null, null, null, null, null, null,
                Instant.now());

        assertThatThrownBy(() -> validator.validate(flow))
                .isInstanceOf(FlowValidationException.class)
                .satisfies(ex -> {
                    FlowValidationException fve = (FlowValidationException) ex;
                    org.assertj.core.api.Assertions.assertThat(fve.reason()).isEqualTo("missing_field");
                });
    }

    @Test
    @DisplayName("Missing tsStart → FlowValidationException")
    void validate_missingTsStart_throwsException() {
        NormalizedFlow flow = new NormalizedFlow(
                UUID.randomUUID(), null, TS_END, DURATION_MS,
                "10.20.30.40", 54321, "93.184.216.34", 443,
                "tcp", 18432L, 24L, 0x1b,
                false, null, null,
                "netflow-v5", "10.0.0.1",
                null, null, null, null, null, null,
                Instant.now());

        assertThatThrownBy(() -> validator.validate(flow))
                .isInstanceOf(FlowValidationException.class)
                .satisfies(ex -> {
                    FlowValidationException fve = (FlowValidationException) ex;
                    org.assertj.core.api.Assertions.assertThat(fve.reason()).isEqualTo("missing_field");
                });
    }

    @Test
    @DisplayName("Invalid srcIp → FlowValidationException(invalid_ip)")
    void validate_invalidSrcIp_throwsException() {
        NormalizedFlow flow = new NormalizedFlow(
                UUID.randomUUID(), TS_START, TS_END, DURATION_MS,
                "not-an-ip", 54321, "93.184.216.34", 443,
                "tcp", 18432L, 24L, 0x1b,
                false, null, null,
                "netflow-v5", "10.0.0.1",
                null, null, null, null, null, null,
                Instant.now());

        assertThatThrownBy(() -> validator.validate(flow))
                .isInstanceOf(FlowValidationException.class)
                .satisfies(ex -> {
                    FlowValidationException fve = (FlowValidationException) ex;
                    org.assertj.core.api.Assertions.assertThat(fve.reason()).isEqualTo("invalid_ip");
                });
    }

    @Test
    @DisplayName("Invalid exporterIp -> FlowValidationException(invalid_ip)")
    void validate_invalidExporterIp_throwsException() {
        NormalizedFlow flow = new NormalizedFlow(
                UUID.randomUUID(), TS_START, TS_END, DURATION_MS,
                "10.20.30.40", 54321, "93.184.216.34", 443,
                "tcp", 18432L, 24L, 0x1b,
                false, null, null,
                "netflow-v5", "not-an-ip",
                null, null, null, null, null, null,
                Instant.now());

        assertThatThrownBy(() -> validator.validate(flow))
                .isInstanceOf(FlowValidationException.class)
                .satisfies(ex -> {
                    FlowValidationException fve = (FlowValidationException) ex;
                    org.assertj.core.api.Assertions.assertThat(fve.reason()).isEqualTo("invalid_ip");
                });
    }

    @Test
    @DisplayName("Port out of range → FlowValidationException(invalid_port)")
    void validate_portOutOfRange_throwsException() {
        NormalizedFlow flow = new NormalizedFlow(
                UUID.randomUUID(), TS_START, TS_END, DURATION_MS,
                "10.20.30.40", 70000, "93.184.216.34", 443,
                "tcp", 18432L, 24L, 0x1b,
                false, null, null,
                "netflow-v5", "10.0.0.1",
                null, null, null, null, null, null,
                Instant.now());

        assertThatThrownBy(() -> validator.validate(flow))
                .isInstanceOf(FlowValidationException.class)
                .satisfies(ex -> {
                    FlowValidationException fve = (FlowValidationException) ex;
                    org.assertj.core.api.Assertions.assertThat(fve.reason()).isEqualTo("invalid_port");
                });
    }

    @Test
    @DisplayName("Negative bytes → FlowValidationException(invalid_counter)")
    void validate_negativeBytes_throwsException() {
        NormalizedFlow flow = new NormalizedFlow(
                UUID.randomUUID(), TS_START, TS_END, DURATION_MS,
                "10.20.30.40", 54321, "93.184.216.34", 443,
                "tcp", -1L, 24L, 0x1b,
                false, null, null,
                "netflow-v5", "10.0.0.1",
                null, null, null, null, null, null,
                Instant.now());

        assertThatThrownBy(() -> validator.validate(flow))
                .isInstanceOf(FlowValidationException.class)
                .satisfies(ex -> {
                    FlowValidationException fve = (FlowValidationException) ex;
                    org.assertj.core.api.Assertions.assertThat(fve.reason()).isEqualTo("invalid_counter");
                });
    }

    @Test
    @DisplayName("tsStart after tsEnd → FlowValidationException(invalid_timestamp)")
    void validate_tsStartAfterTsEnd_throwsException() {
        NormalizedFlow flow = new NormalizedFlow(
                UUID.randomUUID(), TS_END, TS_START, DURATION_MS,
                "10.20.30.40", 54321, "93.184.216.34", 443,
                "tcp", 18432L, 24L, 0x1b,
                false, null, null,
                "netflow-v5", "10.0.0.1",
                null, null, null, null, null, null,
                Instant.now());

        assertThatThrownBy(() -> validator.validate(flow))
                .isInstanceOf(FlowValidationException.class)
                .satisfies(ex -> {
                    FlowValidationException fve = (FlowValidationException) ex;
                    org.assertj.core.api.Assertions.assertThat(fve.reason()).isEqualTo("invalid_timestamp");
                });
    }

    @Test
    @DisplayName("Duration mismatch → FlowValidationException(invalid_duration)")
    void validate_durationMismatch_throwsException() {
        NormalizedFlow flow = new NormalizedFlow(
                UUID.randomUUID(), TS_START, TS_END, 9999L,  // wrong duration
                "10.20.30.40", 54321, "93.184.216.34", 443,
                "tcp", 18432L, 24L, 0x1b,
                false, null, null,
                "netflow-v5", "10.0.0.1",
                null, null, null, null, null, null,
                Instant.now());

        assertThatThrownBy(() -> validator.validate(flow))
                .isInstanceOf(FlowValidationException.class)
                .satisfies(ex -> {
                    FlowValidationException fve = (FlowValidationException) ex;
                    org.assertj.core.api.Assertions.assertThat(fve.reason()).isEqualTo("invalid_duration");
                });
    }

    @Test
    @DisplayName("tcpFlags on non-TCP protocol → FlowValidationException(invalid_tcp_flags)")
    void validate_tcpFlagsOnNonTcp_throwsException() {
        NormalizedFlow flow = new NormalizedFlow(
                UUID.randomUUID(), TS_START, TS_END, DURATION_MS,
                "10.20.30.40", 54321, "93.184.216.34", 443,
                "udp", 18432L, 24L, 27,
                false, null, null,
                "netflow-v5", "10.0.0.1",
                null, null, null, null, null, null,
                Instant.now());

        assertThatThrownBy(() -> validator.validate(flow))
                .isInstanceOf(FlowValidationException.class)
                .satisfies(ex -> {
                    FlowValidationException fve = (FlowValidationException) ex;
                    org.assertj.core.api.Assertions.assertThat(fve.reason()).isEqualTo("invalid_tcp_flags");
                });
    }

    @Test
    @DisplayName("tcpFlags out of range → FlowValidationException(invalid_tcp_flags)")
    void validate_tcpFlagsOutOfRange_throwsException() {
        NormalizedFlow flow = new NormalizedFlow(
                UUID.randomUUID(), TS_START, TS_END, DURATION_MS,
                "10.20.30.40", 54321, "93.184.216.34", 443,
                "tcp", 18432L, 24L, 99999,
                false, null, null,
                "netflow-v5", "10.0.0.1",
                null, null, null, null, null, null,
                Instant.now());

        assertThatThrownBy(() -> validator.validate(flow))
                .isInstanceOf(FlowValidationException.class)
                .satisfies(ex -> {
                    FlowValidationException fve = (FlowValidationException) ex;
                    org.assertj.core.api.Assertions.assertThat(fve.reason()).isEqualTo("invalid_tcp_flags");
                });
    }

    @Test
    @DisplayName("Sampled without rate → FlowValidationException(invalid_sampling)")
    void validate_sampledWithoutRate_throwsException() {
        NormalizedFlow flow = new NormalizedFlow(
                UUID.randomUUID(), TS_START, TS_END, DURATION_MS,
                "10.20.30.40", 54321, "93.184.216.34", 443,
                "tcp", 18432L, 24L, 0x1b,
                true, null, null,
                "netflow-v5", "10.0.0.1",
                null, null, null, null, null, null,
                Instant.now());

        assertThatThrownBy(() -> validator.validate(flow))
                .isInstanceOf(FlowValidationException.class)
                .satisfies(ex -> {
                    FlowValidationException fve = (FlowValidationException) ex;
                    org.assertj.core.api.Assertions.assertThat(fve.reason()).isEqualTo("invalid_sampling");
                });
    }

    @Test
    @DisplayName("Unsampled with rate → FlowValidationException(invalid_sampling)")
    void validate_unsampledWithRate_throwsException() {
        NormalizedFlow flow = new NormalizedFlow(
                UUID.randomUUID(), TS_START, TS_END, DURATION_MS,
                "10.20.30.40", 54321, "93.184.216.34", 443,
                "tcp", 18432L, 24L, 0x1b,
                false, 100L, null,
                "netflow-v5", "10.0.0.1",
                null, null, null, null, null, null,
                Instant.now());

        assertThatThrownBy(() -> validator.validate(flow))
                .isInstanceOf(FlowValidationException.class)
                .satisfies(ex -> {
                    FlowValidationException fve = (FlowValidationException) ex;
                    org.assertj.core.api.Assertions.assertThat(fve.reason()).isEqualTo("invalid_sampling");
                });
    }

    @Test
    @DisplayName("Invalid country code -> FlowValidationException(invalid_enrichment)")
    void validate_invalidCountryCode_throwsException() {
        NormalizedFlow flow = validFlow().withEnrichment("usa", null, null, null, null, null);

        assertThatThrownBy(() -> validator.validate(flow))
                .isInstanceOf(FlowValidationException.class)
                .satisfies(ex -> {
                    FlowValidationException fve = (FlowValidationException) ex;
                    org.assertj.core.api.Assertions.assertThat(fve.reason()).isEqualTo("invalid_enrichment");
                });
    }

    @Test
    @DisplayName("ASN out of range -> FlowValidationException(invalid_enrichment)")
    void validate_asnOutOfRange_throwsException() {
        NormalizedFlow flow = validFlow().withEnrichment(null, 4_294_967_296L, null, null, null, null);

        assertThatThrownBy(() -> validator.validate(flow))
                .isInstanceOf(FlowValidationException.class)
                .satisfies(ex -> {
                    FlowValidationException fve = (FlowValidationException) ex;
                    org.assertj.core.api.Assertions.assertThat(fve.reason()).isEqualTo("invalid_enrichment");
                });
    }

    @Test
    @DisplayName("IPv6 addresses → accepted without exception")
    void validate_ipv6Addresses_accepted() {
        NormalizedFlow flow = new NormalizedFlow(
                UUID.randomUUID(), TS_START, TS_END, DURATION_MS,
                "::1", 54321, "fe80::1", 443,
                "tcp", 18432L, 24L, 0x1b,
                false, null, null,
                "netflow-v5", "10.0.0.1",
                null, null, null, null, null, null,
                Instant.now());

        assertThatCode(() -> validator.validate(flow))
                .doesNotThrowAnyException();
    }
}
