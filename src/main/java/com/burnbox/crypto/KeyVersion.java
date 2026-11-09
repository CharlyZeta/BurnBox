package com.burnbox.crypto;

import java.util.Objects;

public record KeyVersion(int version, KeyStatus status, byte[] kek) {
    public KeyVersion {
        Objects.requireNonNull(status, "status must not be null");
        Objects.requireNonNull(kek, "kek must not be null");
        if (kek.length != 32) {
            throw new IllegalArgumentException("KEK must be exactly 256 bits (32 bytes)");
        }
    }
}
