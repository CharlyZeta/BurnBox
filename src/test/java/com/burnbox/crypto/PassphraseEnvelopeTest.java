package com.burnbox.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class PassphraseEnvelopeTest {

    @Test
    @DisplayName("BR-004 & AC-004: Double wrapping DEK with passphrase-derived key and active KEK")
    void doubleWrappingAndUnwrappingWithCorrectPassphrase() {
        LocalKeyProvider keyProvider = new LocalKeyProvider();
        CryptoTokenService tokenService = new CryptoTokenService();
        PassphraseKeyDeriver keyDeriver = new PassphraseKeyDeriver();
        SecretEnvelopeService service = new SecretEnvelopeService(keyProvider, tokenService, keyDeriver);

        UUID secretId = UUID.randomUUID();
        byte[] plaintext = "Sensitive data protected with Argon2id passphrase".getBytes(StandardCharsets.UTF_8);
        char[] passphrase = "my-secret-vault-password".toCharArray();

        SecretEnvelopeService.EncryptionResult result = service.encrypt(plaintext, secretId, 1, passphrase);
        assertNotNull(result.envelope());
        assertNotNull(result.passphraseSalt());
        assertEquals(16, result.passphraseSalt().length);

        // Decrypt with correct passphrase
        byte[] decrypted = service.decrypt(result.envelope(), secretId, passphrase, result.passphraseSalt());
        assertArrayEquals(plaintext, decrypted, "Decrypted payload must match original plaintext");
    }

    @Test
    @DisplayName("BR-006 & AF-01: Incorrect passphrase fails AESWrap integrity check and throws CryptoException")
    void incorrectPassphraseFailsIntegrityCheck() {
        LocalKeyProvider keyProvider = new LocalKeyProvider();
        CryptoTokenService tokenService = new CryptoTokenService();
        PassphraseKeyDeriver keyDeriver = new PassphraseKeyDeriver();
        SecretEnvelopeService service = new SecretEnvelopeService(keyProvider, tokenService, keyDeriver);

        UUID secretId = UUID.randomUUID();
        byte[] plaintext = "Highly classified document".getBytes(StandardCharsets.UTF_8);
        char[] correctPassphrase = "correct-passphrase-123".toCharArray();
        char[] wrongPassphrase = "wrong-passphrase-999".toCharArray();

        SecretEnvelopeService.EncryptionResult result = service.encrypt(plaintext, secretId, 1, correctPassphrase);

        CryptoException ex = assertThrows(CryptoException.class, () ->
                service.decrypt(result.envelope(), secretId, wrongPassphrase, result.passphraseSalt())
        );
        assertTrue(ex.getMessage().contains("invalid passphrase") || ex.getMessage().contains("corrupted"));
    }
}
