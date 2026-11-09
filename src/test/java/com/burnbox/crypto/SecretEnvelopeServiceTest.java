package com.burnbox.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SecretEnvelopeServiceTest {

    private final LocalKeyProvider keyProvider = new LocalKeyProvider();
    private final CryptoTokenService tokenService = new CryptoTokenService();
    private final PassphraseKeyDeriver keyDeriver = new PassphraseKeyDeriver();
    private final SecretEnvelopeService envelopeService = new SecretEnvelopeService(keyProvider, tokenService, keyDeriver);

    @Test
    @DisplayName("AC-003 / AC-004 / BR-004 / BR-005: Cifrado y descifrado de texto de hasta 64 KiB con AAD correcto")
    void encryptAndDecryptRoundtripSuccess() throws Exception {
        UUID secretId = UUID.randomUUID();
        String secretText = "SuperSecretPassword123!_".repeat(2000); // ~48 KiB
        byte[] plaintext = secretText.getBytes(StandardCharsets.UTF_8);

        SecretEnvelope envelope = envelopeService.encrypt(plaintext, secretId, 1);

        assertThat(envelope.ciphertext()).isNotEmpty();
        assertThat(envelope.nonce()).hasSize(12); // 96 bits
        assertThat(envelope.wrappedDek()).isNotEmpty();
        assertThat(envelope.keyVersion()).isEqualTo(1);
        assertThat(envelope.formatVersion()).isEqualTo(1);

        byte[] decrypted = envelopeService.decrypt(envelope, secretId);
        assertThat(new String(decrypted, StandardCharsets.UTF_8)).isEqualTo(secretText);
    }

    @Test
    @DisplayName("AC-005 / AF-01: Descifrado con AAD alterado (otro secretId) falla por autenticidad")
    void decryptWithAlteredSecretIdFails() {
        UUID originalSecretId = UUID.randomUUID();
        UUID attackerSecretId = UUID.randomUUID();
        byte[] plaintext = "ConfidentialData".getBytes(StandardCharsets.UTF_8);

        SecretEnvelope envelope = envelopeService.encrypt(plaintext, originalSecretId, 1);

        assertThatThrownBy(() -> envelopeService.decrypt(envelope, attackerSecretId))
                .isInstanceOf(CryptoException.class)
                .hasCauseInstanceOf(AEADBadTagException.class);
    }

    @Test
    @DisplayName("AC-006 / AF-02: Descifrado con manipulación de 1 bit en ciphertext (tampering) falla")
    void decryptWithTamperedCiphertextFails() {
        UUID secretId = UUID.randomUUID();
        byte[] plaintext = "IntegrityCheckPayload".getBytes(StandardCharsets.UTF_8);

        SecretEnvelope envelope = envelopeService.encrypt(plaintext, secretId, 1);

        byte[] tamperedCiphertext = envelope.ciphertext().clone();
        tamperedCiphertext[0] ^= 0x01; // Invertir 1 bit

        SecretEnvelope tamperedEnvelope = new SecretEnvelope(
                tamperedCiphertext,
                envelope.nonce(),
                envelope.wrappedDek(),
                envelope.keyVersion(),
                envelope.formatVersion()
        );

        assertThatThrownBy(() -> envelopeService.decrypt(tamperedEnvelope, secretId))
                .isInstanceOf(CryptoException.class)
                .hasCauseInstanceOf(AEADBadTagException.class);
    }

    @Test
    @DisplayName("AC-006 / AF-02: Descifrado con manipulación en el nonce falla")
    void decryptWithTamperedNonceFails() {
        UUID secretId = UUID.randomUUID();
        byte[] plaintext = "NonceIntegrityPayload".getBytes(StandardCharsets.UTF_8);

        SecretEnvelope envelope = envelopeService.encrypt(plaintext, secretId, 1);

        byte[] tamperedNonce = envelope.nonce().clone();
        tamperedNonce[0] ^= 0x01;

        SecretEnvelope tamperedEnvelope = new SecretEnvelope(
                envelope.ciphertext(),
                tamperedNonce,
                envelope.wrappedDek(),
                envelope.keyVersion(),
                envelope.formatVersion()
        );

        assertThatThrownBy(() -> envelopeService.decrypt(tamperedEnvelope, secretId))
                .isInstanceOf(CryptoException.class)
                .hasCauseInstanceOf(AEADBadTagException.class);
    }
}
