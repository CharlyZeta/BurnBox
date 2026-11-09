package com.burnbox.secret;

/**
 * BR-007: Pure domain sealed result hierarchy for exhaustive handling of secret access attempts.
 */
public sealed interface SecretAccessResult permits
        SecretAccessResult.Success,
        SecretAccessResult.NotAvailable {

    record Success(
            byte[] plaintext,
            int views,
            int maxViews,
            SecretState state
    ) implements SecretAccessResult {
    }

    record NotAvailable(
            String reason
    ) implements SecretAccessResult {
    }
}
