package com.burnbox;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.assertj.core.api.Assertions.assertThat;

class ComposeConfigTest {

    @Test
    @DisplayName("AC-001: compose.yaml define PostgreSQL y Mailpit con puertos e imágenes correctos")
    void composeDefinesRequiredServices() throws IOException {
        Path composePath = Paths.get("compose.yaml");
        assertThat(Files.exists(composePath)).isTrue();

        String content = Files.readString(composePath);
        assertThat(content)
                .contains("postgres:")
                .contains("image: postgres:")
                .contains("5432:5432")
                .contains("POSTGRES_DB: burnbox")
                .contains("healthcheck:")
                .contains("mailpit:")
                .contains("1025:1025")
                .contains("8025:8025");
    }
}
