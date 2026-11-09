package com.burnbox.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HmacIpHasherTest {

    private final HmacIpHasher hasher = new HmacIpHasher("unit-test-salt-12345");

    @Test
    @DisplayName("AF-01 / AC-004: ip_hash es un HMAC-SHA256 de 64 caracteres hexadecimales en minúsculas")
    void hashesIpWithHmacSha256() {
        String hash = hasher.hashIp("192.168.1.50");

        assertThat(hash).hasSize(64);
        assertThat(hash).matches("^[0-9a-f]{64}$");

        // Determinista
        assertThat(hasher.hashIp("192.168.1.50")).isEqualTo(hash);

        // IPs distintas producen hashes distintos
        assertThat(hasher.hashIp("192.168.1.51")).isNotEqualTo(hash);
    }

    @Test
    @DisplayName("AF-01: IP nula o en blanco utiliza dirección por defecto segura")
    void blankIpUsesDefaultSafe() {
        String hashNull = hasher.hashIp(null);
        String hashBlank = hasher.hashIp("   ");

        assertThat(hashNull).isEqualTo(hashBlank);
        assertThat(hashNull).hasSize(64);
    }

    @Test
    @DisplayName("Rechaza sal nula o en blanco")
    void rejectsNullOrBlankSalt() {
        assertThatThrownBy(() -> new HmacIpHasher(null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HmacIpHasher("  "))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
