package com.burnbox.ratelimit;

public sealed interface RateLimitResult {

    record Allowed(long remainingTokens) implements RateLimitResult {
        public boolean isAllowed() {
            return true;
        }
    }

    record Denied(long retryAfterSeconds) implements RateLimitResult {
        public boolean isAllowed() {
            return false;
        }
    }

    default boolean isAllowed() {
        return this instanceof Allowed;
    }
}
