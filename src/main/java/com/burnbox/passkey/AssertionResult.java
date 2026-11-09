package com.burnbox.passkey;

public enum AssertionResult {
    SUCCESS,
    NOT_FOUND,
    NOT_ACTIVE,
    ANOMALY_DETECTED;

    public boolean isSuccessful() {
        return this == SUCCESS;
    }
}
