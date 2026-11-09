package com.burnbox.audit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuditChainTest {

    @Test
    @DisplayName("AC-001 & BR-004: Cálculo determinista de hash SHA-256 para bloque génesis")
    void deterministicGenesisHashCalculation() {
        String genesisHash = AuditHashCalculator.calculateHash(
                AuditHashCalculator.GENESIS_PREV_HASH,
                1731175200000L,
                "SECRET_CREATED",
                UUID.fromString("11111111-1111-1111-1111-111111111111"),
                "secret",
                "sec-123",
                "req-456",
                "ip-hash-abc",
                "{\"max_views\":1}"
        );

        assertThat(genesisHash).hasSize(64);

        // Determinismo: dos llamadas idénticas producen exactamente el mismo hash
        String secondCall = AuditHashCalculator.calculateHash(
                AuditHashCalculator.GENESIS_PREV_HASH,
                1731175200000L,
                "SECRET_CREATED",
                UUID.fromString("11111111-1111-1111-1111-111111111111"),
                "secret",
                "sec-123",
                "req-456",
                "ip-hash-abc",
                "{\"max_views\":1}"
        );

        assertThat(genesisHash).isEqualTo(secondCall);
    }

    @Test
    @DisplayName("AC-005 & BR-001 & BR-005: AuditChainVerifier valida exitosamente una cadena íntegra")
    void verifierValidatesIntactChain() {
        SecurityEventRepository repository = mock(SecurityEventRepository.class);
        AuditChainVerifier verifier = new AuditChainVerifier(repository);

        List<SecurityEventRecord> chain = buildMockChain(5);
        when(repository.findAllOrderedById()).thenReturn(chain);

        AuditVerificationResult result = verifier.verifyChain();
        assertThat(result).isInstanceOf(AuditVerificationResult.Valid.class);

        AuditVerificationResult.Valid valid = (AuditVerificationResult.Valid) result;
        assertThat(valid.totalEvents()).isEqualTo(5);
        assertThat(valid.headHash()).isEqualTo(chain.get(4).hash());
    }

    @Test
    @DisplayName("AC-006 & AF-03: AuditChainVerifier detecta alteración en datos del evento (tampering)")
    void verifierDetectsTamperedData() {
        SecurityEventRepository repository = mock(SecurityEventRepository.class);
        AuditChainVerifier verifier = new AuditChainVerifier(repository);

        List<SecurityEventRecord> chain = buildMockChain(3);
        // Alterar los detalles del segundo evento sin actualizar el hash
        SecurityEventRecord tampered = new SecurityEventRecord(
                chain.get(1).id(),
                chain.get(1).occurredAt(),
                chain.get(1).eventType(),
                chain.get(1).actorUserId(),
                chain.get(1).subjectType(),
                chain.get(1).subjectId(),
                chain.get(1).requestId(),
                chain.get(1).ipHash(),
                "{\"tampered\": true}", // Manipulado
                chain.get(1).prevHash(),
                chain.get(1).hash()
        );
        chain.set(1, tampered);

        when(repository.findAllOrderedById()).thenReturn(chain);

        AuditVerificationResult result = verifier.verifyChain();
        assertThat(result).isInstanceOf(AuditVerificationResult.Broken.class);

        AuditVerificationResult.Broken broken = (AuditVerificationResult.Broken) result;
        assertThat(broken.eventId()).isEqualTo(chain.get(1).id());
        assertThat(broken.reason()).contains("Tampered event data");
    }

    @Test
    @DisplayName("AC-006 & BR-002: AuditChainVerifier detecta eslabón roto en prev_hash")
    void verifierDetectsBrokenPrevHash() {
        SecurityEventRepository repository = mock(SecurityEventRepository.class);
        AuditChainVerifier verifier = new AuditChainVerifier(repository);

        List<SecurityEventRecord> chain = buildMockChain(3);
        // Modificar prev_hash del tercer evento
        SecurityEventRecord brokenLink = new SecurityEventRecord(
                chain.get(2).id(),
                chain.get(2).occurredAt(),
                chain.get(2).eventType(),
                chain.get(2).actorUserId(),
                chain.get(2).subjectType(),
                chain.get(2).subjectId(),
                chain.get(2).requestId(),
                chain.get(2).ipHash(),
                chain.get(2).details(),
                "f".repeat(64), // Enlace roto
                chain.get(2).hash()
        );
        chain.set(2, brokenLink);

        when(repository.findAllOrderedById()).thenReturn(chain);

        AuditVerificationResult result = verifier.verifyChain();
        assertThat(result).isInstanceOf(AuditVerificationResult.Broken.class);

        AuditVerificationResult.Broken broken = (AuditVerificationResult.Broken) result;
        assertThat(broken.eventId()).isEqualTo(chain.get(2).id());
        assertThat(broken.reason()).contains("expected prev_hash");
    }

    private List<SecurityEventRecord> buildMockChain(int count) {
        List<SecurityEventRecord> chain = new ArrayList<>();
        String prevHash = AuditHashCalculator.GENESIS_PREV_HASH;
        Instant start = Instant.parse("2026-11-09T18:00:00Z");

        for (int i = 1; i <= count; i++) {
            Instant time = start.plusSeconds(i * 10L);
            long epoch = time.toEpochMilli();
            String eventType = "EVENT_" + i;
            UUID actor = UUID.randomUUID();
            String details = "{\"index\":" + i + "}";

            String hash = AuditHashCalculator.calculateHash(
                    prevHash,
                    epoch,
                    eventType,
                    actor,
                    "subject",
                    "id-" + i,
                    "req-" + i,
                    "ip-hash",
                    details
            );

            SecurityEventRecord record = new SecurityEventRecord(
                    (long) i,
                    time,
                    eventType,
                    actor,
                    "subject",
                    "id-" + i,
                    "req-" + i,
                    "ip-hash",
                    details,
                    prevHash,
                    hash
            );

            chain.add(record);
            prevHash = hash;
        }

        return chain;
    }
}
