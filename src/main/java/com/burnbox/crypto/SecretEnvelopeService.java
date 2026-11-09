package com.burnbox.crypto;

import org.springframework.stereotype.Service;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Objects;
import java.util.UUID;

@Service
public class SecretEnvelopeService {

    public static final int FORMAT_VERSION = 1;
    public static final int NONCE_LENGTH_BYTES = 12; // 96 bits
    public static final int TAG_LENGTH_BITS = 128;
    public static final int DEK_LENGTH_BYTES = 32;  // 256 bits

    private final KeyProvider keyProvider;
    private final CryptoTokenService tokenService;
    private final PassphraseKeyDeriver passphraseKeyDeriver;

    public SecretEnvelopeService(
            KeyProvider keyProvider,
            CryptoTokenService tokenService,
            PassphraseKeyDeriver passphraseKeyDeriver
    ) {
        this.keyProvider = Objects.requireNonNull(keyProvider, "keyProvider must not be null");
        this.tokenService = Objects.requireNonNull(tokenService, "tokenService must not be null");
        this.passphraseKeyDeriver = Objects.requireNonNull(passphraseKeyDeriver, "passphraseKeyDeriver must not be null");
    }

    public record EncryptionResult(SecretEnvelope envelope, byte[] passphraseSalt) {}

    public SecretEnvelope encrypt(byte[] plaintext, UUID secretId, int keyVersion) {
        return encrypt(plaintext, secretId, keyVersion, null).envelope();
    }

    public EncryptionResult encrypt(byte[] plaintext, UUID secretId, int keyVersion, char[] passphrase) {
        Objects.requireNonNull(plaintext, "plaintext must not be null");
        Objects.requireNonNull(secretId, "secretId must not be null");

        byte[] dek = tokenService.generateBytes(DEK_LENGTH_BYTES);
        byte[] nonce = tokenService.generateBytes(NONCE_LENGTH_BYTES);

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH_BITS, nonce);
            SecretKeySpec keySpec = new SecretKeySpec(dek, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, parameterSpec);

            byte[] aad = buildAad(secretId, keyVersion, FORMAT_VERSION);
            cipher.updateAAD(aad);

            byte[] ciphertext = cipher.doFinal(plaintext);

            byte[] intermediateWrappedDek;
            byte[] salt = null;

            if (passphrase != null && passphrase.length > 0) {
                salt = passphraseKeyDeriver.generateSalt();
                byte[] passphraseKey = passphraseKeyDeriver.deriveKey(passphrase, salt);

                Cipher wrapCipher = Cipher.getInstance("AESWrap");
                wrapCipher.init(Cipher.WRAP_MODE, new SecretKeySpec(passphraseKey, "AES"));
                intermediateWrappedDek = wrapCipher.wrap(keySpec);
            } else {
                intermediateWrappedDek = dek;
            }

            byte[] finalWrappedDek = keyProvider.wrap(intermediateWrappedDek, keyVersion);
            SecretEnvelope envelope = new SecretEnvelope(ciphertext, nonce, finalWrappedDek, keyVersion, FORMAT_VERSION);

            return new EncryptionResult(envelope, salt);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Failed to encrypt secret payload with AES-GCM envelope", e);
        }
    }

    public byte[] decrypt(SecretEnvelope envelope, UUID secretId) {
        return decrypt(envelope, secretId, null, null);
    }

    public byte[] decrypt(SecretEnvelope envelope, UUID secretId, char[] passphrase, byte[] passphraseSalt) {
        Objects.requireNonNull(envelope, "envelope must not be null");
        Objects.requireNonNull(secretId, "secretId must not be null");

        byte[] unwrappedFromKek = keyProvider.unwrap(envelope.wrappedDek(), envelope.keyVersion());
        byte[] dek;

        try {
            if (passphraseSalt != null && passphraseSalt.length > 0) {
                if (passphrase == null || passphrase.length == 0) {
                    throw new CryptoException("Passphrase required to decrypt secret");
                }

                byte[] passphraseKey = passphraseKeyDeriver.deriveKey(passphrase, passphraseSalt);
                Cipher unwrapCipher = Cipher.getInstance("AESWrap");
                unwrapCipher.init(Cipher.UNWRAP_MODE, new SecretKeySpec(passphraseKey, "AES"));
                Key unwrappedKey = unwrapCipher.unwrap(unwrappedFromKek, "AES", Cipher.SECRET_KEY);
                dek = unwrappedKey.getEncoded();
            } else {
                dek = unwrappedFromKek;
            }

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH_BITS, envelope.nonce());
            SecretKeySpec keySpec = new SecretKeySpec(dek, "AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, parameterSpec);

            byte[] aad = buildAad(secretId, envelope.keyVersion(), envelope.formatVersion());
            cipher.updateAAD(aad);

            return cipher.doFinal(envelope.ciphertext());
        } catch (AEADBadTagException e) {
            throw new CryptoException("Authentication tag verification failed: tampering or invalid AAD", e);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Failed to decrypt secret payload: invalid passphrase or corrupted key", e);
        }
    }

    private byte[] buildAad(UUID secretId, int keyVersion, int formatVersion) {
        String aadString = secretId.toString() + ":" + keyVersion + ":" + formatVersion;
        return aadString.getBytes(StandardCharsets.UTF_8);
    }
}
