package com.burnbox.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CryptoTokenServiceTest {

    private final CryptoTokenService service = new CryptoTokenService();

    @Test
    @DisplayName("AC-001 / BR-002: Token generado tiene 43 caracteres base64url sin relleno y 256 bits de entropía")
    void tokenHasExactLengthAndBase64UrlEncoding() {
        String token = service.generateToken();

        assertThat(token).hasSize(43);
        assertThat(token).doesNotContain("=");
        assertThat(token).doesNotContain("+");
        assertThat(token).doesNotContain("/");

        byte[] decoded = Base64.getUrlDecoder().decode(token);
        assertThat(decoded).hasSize(32); // 256 bits
    }

    @Test
    @DisplayName("AC-001: Tokens generados sucesivamente son únicos")
    void tokensAreUnique() {
        Set<String> tokens = new HashSet<>();
        for (int i = 0; i < 1000; i++) {
            tokens.add(service.generateToken());
        }
        assertThat(tokens).hasSize(1000);
    }

    @Test
    @DisplayName("AC-002 / BR-003: Hash SHA-256 es determinista y en formato hexadecimal de 64 caracteres")
    void hashTokenProducesConsistentHex() {
        String token = "abc123DEF456_-abc123DEF456_-abc123DEF456_--";
        String hash1 = service.hashToken(token);
        String hash2 = service.hashToken(token);

        assertThat(hash1).isEqualTo(hash2);
        assertThat(hash1).hasSize(64);
        assertThat(hash1).matches("^[0-9a-f]{64}$");
    }

    @Test
    @DisplayName("HashToken rechaza token nulo o vacío")
    void hashTokenRejectsNullOrBlank() {
        assertThatThrownBy(() -> service.hashToken(null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.hashToken("   "))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
