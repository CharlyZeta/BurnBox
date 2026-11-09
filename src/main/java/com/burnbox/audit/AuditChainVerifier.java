package com.burnbox.audit;

import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Service that verifies the mathematical and cryptographic integrity of the audit hash chain (BR-005).
 */
@Service
public class AuditChainVerifier {

    private final SecurityEventRepository repository;

    public AuditChainVerifier(SecurityEventRepository repository) {
        this.repository = repository;
    }

    public AuditVerificationResult verifyChain() {
        List<SecurityEventRecord> events = repository.findAllOrderedById();
        if (events.isEmpty()) {
            return new AuditVerificationResult.Valid(0, AuditHashCalculator.GENESIS_PREV_HASH);
        }

        String expectedPrevHash = AuditHashCalculator.GENESIS_PREV_HASH;

        for (int i = 0; i < events.size(); i++) {
            SecurityEventRecord event = events.get(i);

            // 1. Validar encadenamiento de hash padre (prev_hash)
            if (!expectedPrevHash.equals(event.prevHash())) {
                return new AuditVerificationResult.Broken(
                        event.id(),
                        "Broken chain at event " + event.id() + ": expected prev_hash " + expectedPrevHash + " but was " + event.prevHash()
                );
            }

            // 2. Recalcular hash canónico
            String recalculatedHash = AuditHashCalculator.calculateHash(
                    event.prevHash(),
                    event.occurredAt().toEpochMilli(),
                    event.eventType(),
                    event.actorUserId(),
                    event.subjectType(),
                    event.subjectId(),
                    event.requestId(),
                    event.ipHash(),
                    event.details()
            );

            if (!recalculatedHash.equals(event.hash())) {
                return new AuditVerificationResult.Broken(
                        event.id(),
                        "Tampered event data at id " + event.id() + ": recalculated hash " + recalculatedHash + " does not match stored hash " + event.hash()
                );
            }

            expectedPrevHash = event.hash();
        }

        SecurityEventRecord head = events.get(events.size() - 1);
        return new AuditVerificationResult.Valid(events.size(), head.hash());
    }
}
