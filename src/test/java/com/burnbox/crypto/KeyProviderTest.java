package com.burnbox.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KeyProviderTest {

    private final LocalKeyProvider keyProvider = new LocalKeyProvider();

    @Test
    @DisplayName("AC-007 / AF-04: Wrap y unwrap con KEK activa recuperan exactamente la DEK original")
    void wrapAndUnwrapRestoreOriginalDek() {
        byte[] dek = new byte[]{
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
        };

        byte[] wrapped = keyProvider.wrap(dek, 1);
        assertThat(wrapped).isNotEqualTo(dek);

        byte[] unwrapped = keyProvider.unwrap(wrapped, 1);
        assertThat(unwrapped).isEqualTo(dek);
    }

    @Test
    @DisplayName("BR-006: Key ring mantiene exactamente una versión ACTIVE")
    void keyRingMaintainsSingleActiveVersion() {
        assertThat(keyProvider.getActiveVersion()).isEqualTo(1);

        byte[] kek2 = new byte[32];
        kek2[0] = 0x42;
        keyProvider.registerKey(new KeyVersion(2, KeyStatus.ACTIVE, kek2));

        assertThat(keyProvider.getActiveVersion()).isEqualTo(2);

        // La versión 1 pasa a ser DECRYPT_ONLY
        byte[] dek = new byte[32];
        assertThatThrownBy(() -> keyProvider.wrap(dek, 1))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Cannot wrap with non-active");
    }

    @Test
    @DisplayName("AF-03: Unwrap con versión RETIRED es rechazado")
    void retiredVersionCannotUnwrap() {
        byte[] kek3 = new byte[32];
        kek3[0] = 0x77;
        keyProvider.registerKey(new KeyVersion(3, KeyStatus.RETIRED, kek3));

        byte[] dummyWrapped = new byte[40];
        assertThatThrownBy(() -> keyProvider.unwrap(dummyWrapped, 3))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Cannot unwrap with RETIRED");
    }

    @Test
    @DisplayName("FEAT-0017 AC-002, AC-007 & BR-003: Rotación de KEK permite descifrar secretos antiguos en modo DECRYPT_ONLY y re-envolver a nueva clave activa")
    void keyRotationAllowsReEnvelopeAndLegacyDecryption() {
        byte[] dek = new byte[32];
        dek[0] = 0x55;
        dek[31] = 0x01;

        // Wrap con KEK v1 activa
        byte[] wrappedV1 = keyProvider.wrap(dek, 1);

        // Rotación a KEK v2
        byte[] kek2 = new byte[32];
        kek2[0] = (byte) 0xAA;
        keyProvider.activateNewKey(2, kek2);

        assertThat(keyProvider.getActiveVersion()).isEqualTo(2);

        // AC-007 / BR-003: Lectura concurrente de secreto en v1 todavía funciona en DECRYPT_ONLY
        byte[] unwrappedFromV1 = keyProvider.unwrap(wrappedV1, 1);
        assertThat(unwrappedFromV1).isEqualTo(dek);

        // AC-002: Re-envolver a KEK v2
        byte[] wrappedV2 = keyProvider.wrap(unwrappedFromV1, 2);
        assertThat(wrappedV2).isNotEqualTo(wrappedV1);

        // Revelar con la nueva envoltura en KEK v2
        byte[] unwrappedFromV2 = keyProvider.unwrap(wrappedV2, 2);
        assertThat(unwrappedFromV2).isEqualTo(dek);
    }
}
