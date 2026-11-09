package com.burnbox.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class PassphraseKeyDeriverTest {

    @Test
    @DisplayName("BR-002: Argon2id KDF derives 256-bit key from 16-byte salt and passphrase")
    void saltGenerationAndArgon2Derivation() {
        PassphraseKeyDeriver deriver = new PassphraseKeyDeriver();

        byte[] salt = deriver.generateSalt();
        assertNotNull(salt);
        assertEquals(16, salt.length, "Salt must be 16 bytes");

        char[] passphrase = "super-secure-passphrase-123".toCharArray();
        byte[] key1 = deriver.deriveKey(passphrase, salt);
        assertNotNull(key1);
        assertEquals(32, key1.length, "Derived key must be 32 bytes (256 bits)");

        // Deterministic derivation for identical passphrase and salt
        byte[] key2 = deriver.deriveKey(passphrase, salt);
        assertArrayEquals(key1, key2, "Same passphrase and salt must produce identical key");

        // Different salt produces completely different key
        byte[] differentSalt = deriver.generateSalt();
        byte[] key3 = deriver.deriveKey(passphrase, differentSalt);
        assertFalse(java.util.Arrays.equals(key1, key3), "Different salt must produce distinct key");
    }

    @Test
    @DisplayName("BR-003 & AC-008: Concurrency limiter bounds simultaneous Argon2id derivations to 4")
    void concurrencyLimitEnforcedViaSemaphore() throws InterruptedException {
        PassphraseKeyDeriver deriver = new PassphraseKeyDeriver();
        assertEquals(4, deriver.getAvailablePermits(), "Initial permits must be 4");

        int tasks = 8;
        ExecutorService executor = Executors.newFixedThreadPool(tasks);
        CountDownLatch latch = new CountDownLatch(tasks);
        AtomicInteger maxObservedConcurrent = new AtomicInteger(0);

        byte[] salt = deriver.generateSalt();
        char[] passphrase = "concurrent-test-passphrase".toCharArray();

        for (int i = 0; i < tasks; i++) {
            executor.submit(() -> {
                try {
                    int inFlight = 4 - deriver.getAvailablePermits();
                    maxObservedConcurrent.updateAndGet(current -> Math.max(current, inFlight));
                    deriver.deriveKey(passphrase, salt);
                } finally {
                    latch.countDown();
                }
            });
        }

        boolean finished = latch.await(15, TimeUnit.SECONDS);
        executor.shutdown();
        assertTrue(finished, "All derivations should finish in reasonable time");
        assertTrue(maxObservedConcurrent.get() <= 4, "Concurrent derivations must never exceed 4");
        assertEquals(4, deriver.getAvailablePermits(), "All permits must be released after completion");
    }
}
