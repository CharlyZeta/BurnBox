package com.burnbox.audit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.UUID;

/**
 * Deterministic canonical SHA-256 calculator for the audit hash chain (BR-001, BR-004).
 */
public final class AuditHashCalculator {

    public static final String GENESIS_PREV_HASH = "0".repeat(64);

    private AuditHashCalculator() {}

    public static String calculateHash(
            String prevHash,
            long epochMilli,
            String eventType,
            UUID actorUserId,
            String subjectType,
            String subjectId,
            String requestId,
            String ipHash,
            String detailsJson
    ) {
        String safePrev = (prevHash != null && !prevHash.isBlank()) ? prevHash : GENESIS_PREV_HASH;
        String safeActor = (actorUserId != null) ? actorUserId.toString() : "";
        String safeSubjType = (subjectType != null) ? subjectType : "";
        String safeSubjId = (subjectId != null) ? subjectId : "";
        String safeReqId = (requestId != null) ? requestId : "";
        String safeIpHash = (ipHash != null) ? ipHash : "";
        String safeDetails = (detailsJson != null) ? detailsJson.trim() : "{}";

        String canonicalPayload = String.join(":",
                safePrev,
                String.valueOf(epochMilli),
                eventType != null ? eventType : "",
                safeActor,
                safeSubjType,
                safeSubjId,
                safeReqId,
                safeIpHash,
                safeDetails
        );

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(canonicalPayload.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm must be available in standard JVM", e);
        }
    }
}
