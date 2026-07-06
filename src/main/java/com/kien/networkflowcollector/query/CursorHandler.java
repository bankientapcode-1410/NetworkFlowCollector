package com.kien.networkflowcollector.query;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kien.networkflowcollector.storage.FlowCursor;
import com.kien.networkflowcollector.storage.FlowQuery;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class CursorHandler {

    private static final int VERSION = 1;
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private final ObjectMapper objectMapper;
    private final byte[] secret;

    public CursorHandler(
            ObjectMapper objectMapper,
            @Value("${nfc.query.cursor-secret:network-flow-collector-query-cursor-secret}") String cursorSecret) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
        String secretText =
                cursorSecret == null || cursorSecret.isBlank()
                        ? "network-flow-collector-query-cursor-secret"
                        : cursorSecret;
        this.secret = secretText.getBytes(StandardCharsets.UTF_8);
    }

    public String encode(FlowCursor cursor, FlowQuery query, String sort) {
        Objects.requireNonNull(cursor, "cursor");
        validateCursor(cursor);
        CursorPayload payload =
                new CursorPayload(
                        VERSION,
                        cursor.tsStart(),
                        cursor.flowId(),
                        cursor.limit(),
                        fingerprint(query, sort));
        try {
            String payloadPart = ENCODER.encodeToString(objectMapper.writeValueAsBytes(payload));
            return payloadPart + "." + signature(payloadPart);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unable to encode flow cursor", e);
        }
    }

    public FlowCursor decode(String token, FlowQuery query, String sort) {
        String text = token == null ? "" : token.trim();
        String[] parts = text.split("\\.", -1);
        if (parts.length != 2 || parts[0].isBlank() || parts[1].isBlank()) {
            throw invalidCursor();
        }
        if (!signatureMatches(parts[0], parts[1])) {
            throw invalidCursor();
        }
        try {
            CursorPayload payload =
                    objectMapper.readValue(DECODER.decode(parts[0]), CursorPayload.class);
            validatePayload(payload, query, sort);
            return new FlowCursor(payload.tsStart(), payload.flowId(), payload.limit());
        } catch (IllegalArgumentException | IOException e) {
            throw invalidCursor();
        }
    }

    private void validatePayload(CursorPayload payload, FlowQuery query, String sort) {
        if (payload.version() != VERSION
                || payload.tsStart() == null
                || payload.flowId() == null
                || payload.limit() < 1
                || payload.limit() > FlowQueryBuilder.MAX_FLOW_LIMIT
                || !fingerprint(query, sort).equals(payload.filterHash())) {
            throw invalidCursor();
        }
    }

    private static void validateCursor(FlowCursor cursor) {
        if (cursor.tsStart() == null
                || cursor.flowId() == null
                || cursor.limit() < 1
                || cursor.limit() > FlowQueryBuilder.MAX_FLOW_LIMIT) {
            throw new IllegalArgumentException("cursor requires tsStart, flowId, and a valid limit");
        }
    }

    private boolean signatureMatches(String payloadPart, String signaturePart) {
        byte[] expected = signature(payloadPart).getBytes(StandardCharsets.US_ASCII);
        byte[] actual = signaturePart.getBytes(StandardCharsets.US_ASCII);
        return MessageDigest.isEqual(expected, actual);
    }

    private String signature(String payloadPart) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(secret, HMAC_ALGORITHM));
            return ENCODER.encodeToString(mac.doFinal(payloadPart.getBytes(StandardCharsets.US_ASCII)));
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unable to sign flow cursor", e);
        }
    }

    private static String fingerprint(FlowQuery query, String sort) {
        Objects.requireNonNull(query, "query");
        String canonical =
                String.join(
                        "\n",
                        query.from().toString(),
                        query.to().toString(),
                        text(query.srcIp()),
                        intText(query.srcPort()),
                        text(query.dstIp()),
                        intText(query.dstPort()),
                        lowerText(query.protocol()),
                        text(query.sourceType()),
                        lowerText(sort));
        return sha256(canonical);
    }

    private static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return ENCODER.encodeToString(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    private static String text(String value) {
        return value == null ? "" : value.trim();
    }

    private static String lowerText(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    private static String intText(Integer value) {
        return value == null ? "" : value.toString();
    }

    private static QueryValidationException invalidCursor() {
        return new QueryValidationException(
                "INVALID_CURSOR", "cursor is invalid, expired, or does not match the query filters");
    }

    private record CursorPayload(
            int version,
            @JsonProperty("ts_start") Instant tsStart,
            @JsonProperty("flow_id") UUID flowId,
            int limit,
            @JsonProperty("filter_hash") String filterHash) {}
}
