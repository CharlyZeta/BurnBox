package com.burnbox.crypto;

import java.util.Objects;

public record SecretEnvelope(
        byte[] ciphertext,
        byte[] nonce,
        byte[] wrappedDek,
        int keyVersion,
        int formatVersion
) {
    public SecretEnvelope {
        Objects.requireNonNull(ciphertext, "ciphertext must not be null");
        Objects.requireNonNull(nonce, "nonce must not be null");
        Objects.requireNonNull(wrappedDek, "wrappedDek must not be null");
    }
}
