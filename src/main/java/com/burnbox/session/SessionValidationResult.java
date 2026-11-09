package com.burnbox.session;

public enum SessionValidationResult {
    VALID,
    NOT_FOUND,
    REVOKED,
    EXPIRED_INACTIVITY,
    EXPIRED_ABSOLUTE;

    public boolean isValid() {
        return this == VALID;
    }
}
