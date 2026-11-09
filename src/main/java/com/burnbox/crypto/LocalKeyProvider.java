package com.burnbox.crypto;

import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class LocalKeyProvider implements KeyProvider {

    private final Map<Integer, KeyVersion> keyRing = new ConcurrentHashMap<>();
    private volatile int activeVersion = 1;

    public LocalKeyProvider() {
        // Inicializa con variable de entorno o clave por defecto de 256 bits si no está definida
        String envKek = System.getenv("BURNBOX_KEK_V1");
        byte[] kek;
        if (envKek != null && !envKek.isBlank()) {
            kek = Base64.getDecoder().decode(envKek);
        } else {
            // Clave base de 32 bytes para entorno de desarrollo/test local
            kek = new byte[]{
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
            };
        }
        registerKey(new KeyVersion(1, KeyStatus.ACTIVE, kek));
    }

    public LocalKeyProvider(Map<Integer, KeyVersion> initialKeyRing) {
        initialKeyRing.values().forEach(this::registerKey);
    }

    public synchronized void registerKey(KeyVersion keyVersion) {
        if (keyVersion.status() == KeyStatus.ACTIVE) {
            // Asegura que solo exista exactamente una versión ACTIVE
            for (Map.Entry<Integer, KeyVersion> entry : keyRing.entrySet()) {
                if (entry.getValue().status() == KeyStatus.ACTIVE && entry.getKey() != keyVersion.version()) {
                    keyRing.put(entry.getKey(), new KeyVersion(entry.getKey(), KeyStatus.DECRYPT_ONLY, entry.getValue().kek()));
                }
            }
            this.activeVersion = keyVersion.version();
        }
        keyRing.put(keyVersion.version(), keyVersion);
    }

    @Override
    public byte[] wrap(byte[] dek, int version) {
        KeyVersion keyVersion = getKeyVersion(version);
        if (keyVersion.status() != KeyStatus.ACTIVE) {
            throw new IllegalStateException("Cannot wrap with non-active KEK version: " + version);
        }
        try {
            Cipher cipher = Cipher.getInstance("AESWrap");
            SecretKey kekSpec = new SecretKeySpec(keyVersion.kek(), "AES");
            cipher.init(Cipher.WRAP_MODE, kekSpec);
            SecretKey dekSpec = new SecretKeySpec(dek, "AES");
            return cipher.wrap(dekSpec);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Failed to wrap DEK with KEK version " + version, e);
        }
    }

    @Override
    public byte[] unwrap(byte[] wrappedDek, int version) {
        KeyVersion keyVersion = getKeyVersion(version);
        if (keyVersion.status() == KeyStatus.RETIRED) {
            throw new IllegalStateException("Cannot unwrap with RETIRED KEK version: " + version);
        }
        try {
            Cipher cipher = Cipher.getInstance("AESWrap");
            SecretKey kekSpec = new SecretKeySpec(keyVersion.kek(), "AES");
            cipher.init(Cipher.UNWRAP_MODE, kekSpec);
            return cipher.unwrap(wrappedDek, "AES", Cipher.SECRET_KEY).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Failed to unwrap DEK with KEK version " + version, e);
        }
    }

    @Override
    public int getActiveVersion() {
        return activeVersion;
    }

    @Override
    public synchronized void activateNewKey(int version, byte[] kek) {
        registerKey(new KeyVersion(version, KeyStatus.ACTIVE, kek));
    }

    private KeyVersion getKeyVersion(int version) {
        KeyVersion keyVersion = keyRing.get(version);
        if (keyVersion == null) {
            throw new IllegalArgumentException("Key version not found: " + version);
        }
        return keyVersion;
    }
}
