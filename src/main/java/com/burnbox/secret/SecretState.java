package com.burnbox.secret;

/**
 * Lifecycle states of a Secret.
 * Any state other than ACTIVE is terminal and requires complete clearing of sensitive columns.
 */
public enum SecretState {
    ACTIVE,
    CONSUMED,
    EXPIRED,
    DESTROYED_BY_ABUSE,
    DELETED_BY_OWNER;

    public boolean isTerminal() {
        return this != ACTIVE;
    }
}
