package com.burnbox.identity;

public sealed interface ProvisioningResult {

    record Success(
            AppUser user,
            boolean newlyRegistered,
            boolean pendingDeletionWarning
    ) implements ProvisioningResult {
        public boolean isSuccessful() {
            return true;
        }
    }

    record RejectedDisabled(
            String reason
    ) implements ProvisioningResult {
        public boolean isSuccessful() {
            return false;
        }
    }

    record CollisionBlocked(
            String email,
            String existingProvider
    ) implements ProvisioningResult {
        public boolean isSuccessful() {
            return false;
        }
    }

    default boolean isSuccessful() {
        return this instanceof Success;
    }
}
