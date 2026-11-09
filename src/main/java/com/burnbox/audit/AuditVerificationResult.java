package com.burnbox.audit;

public sealed interface AuditVerificationResult permits
        AuditVerificationResult.Valid,
        AuditVerificationResult.Broken {

    boolean isValid();

    record Valid(int totalEvents, String headHash) implements AuditVerificationResult {
        @Override
        public boolean isValid() {
            return true;
        }
    }

    record Broken(Long eventId, String reason) implements AuditVerificationResult {
        @Override
        public boolean isValid() {
            return false;
        }
    }
}
