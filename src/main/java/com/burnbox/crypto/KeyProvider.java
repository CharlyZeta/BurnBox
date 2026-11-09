package com.burnbox.crypto;

public interface KeyProvider {

    byte[] wrap(byte[] dek, int version);

    byte[] unwrap(byte[] wrappedDek, int version);

    int getActiveVersion();
}
