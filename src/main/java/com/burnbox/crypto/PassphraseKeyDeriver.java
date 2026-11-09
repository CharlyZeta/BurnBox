package com.burnbox.crypto;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.springframework.stereotype.Component;

import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.Semaphore;

/**
 * Argon2id KDF derivation component.
 * Parameters specified by project constitution and Section 13:
 * - 19 MiB memory (19,456 KiB)
 * - 2 iterations
 * - 1 parallelism lane
 * - 16 bytes cryptographic salt
 * - 32 bytes (256 bits) derived key
 * Concurrency is strictly bounded to at most 4 simultaneous derivations via Semaphore.
 */
@Component
public class PassphraseKeyDeriver {

    public static final int SALT_LENGTH_BYTES = 16;
    public static final int DERIVED_KEY_LENGTH_BYTES = 32; // 256 bits
    public static final int MEMORY_KIB = 19 * 1024; // 19 MiB
    public static final int ITERATIONS = 2;
    public static final int PARALLELISM = 1;
    public static final int MAX_CONCURRENT_DERIVATIONS = 4;

    private final SecureRandom secureRandom = new SecureRandom();
    private final Semaphore concurrencyLimiter = new Semaphore(MAX_CONCURRENT_DERIVATIONS, true);

    public byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        secureRandom.nextBytes(salt);
        return salt;
    }

    public byte[] deriveKey(char[] passphrase, byte[] salt) {
        Objects.requireNonNull(passphrase, "passphrase must not be null");
        Objects.requireNonNull(salt, "salt must not be null");

        if (salt.length < SALT_LENGTH_BYTES) {
            throw new IllegalArgumentException("Salt must be at least " + SALT_LENGTH_BYTES + " bytes");
        }

        try {
            concurrencyLimiter.acquire();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new CryptoException("Argon2id key derivation interrupted", e);
        }

        byte[] passphraseBytes = null;
        try {
            // Encode chars to UTF-8 bytes avoiding String pooling
            CharBuffer charBuffer = CharBuffer.wrap(passphrase);
            var byteBuffer = StandardCharsets.UTF_8.encode(charBuffer);
            passphraseBytes = new byte[byteBuffer.remaining()];
            byteBuffer.get(passphraseBytes);

            Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                    .withMemoryAsKB(MEMORY_KIB)
                    .withIterations(ITERATIONS)
                    .withParallelism(PARALLELISM)
                    .withSalt(salt)
                    .build();

            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.init(params);

            byte[] derivedKey = new byte[DERIVED_KEY_LENGTH_BYTES];
            generator.generateBytes(passphraseBytes, derivedKey, 0, derivedKey.length);

            return derivedKey;
        } finally {
            if (passphraseBytes != null) {
                Arrays.fill(passphraseBytes, (byte) 0);
            }
            concurrencyLimiter.release();
        }
    }

    public int getAvailablePermits() {
        return concurrencyLimiter.availablePermits();
    }
}
