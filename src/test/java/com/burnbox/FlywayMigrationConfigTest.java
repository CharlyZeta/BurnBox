package com.burnbox;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class FlywayMigrationConfigTest {

    @Test
    @DisplayName("BR-007: Esquema versionado con Flyway en src/main/resources/db/migration/")
    void migrationDirectoryContainsBaseline() throws IOException {
        Path migrationDir = Paths.get("src/main/resources/db/migration");
        assertThat(Files.exists(migrationDir)).isTrue();
        assertThat(Files.isDirectory(migrationDir)).isTrue();

        try (Stream<Path> files = Files.list(migrationDir)) {
            List<String> fileNames = files.map(p -> p.getFileName().toString()).toList();
            assertThat(fileNames)
                    .isNotEmpty()
                    .anyMatch(name -> name.startsWith("V1__") && name.endsWith(".sql"));
        }
    }
}
