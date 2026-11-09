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

class TemplateSecurityTest {

    @Test
    @DisplayName("BR-004: Prohibido th:utext en todas las plantillas Thymeleaf")
    void noUtextAllowedInTemplates() throws IOException {
        Path templateDir = Paths.get("src/main/resources/templates");
        if (!Files.exists(templateDir)) {
            return;
        }

        try (Stream<Path> paths = Files.walk(templateDir)) {
            List<Path> templates = paths.filter(Files::isRegularFile)
                    .filter(p -> p.toString().endsWith(".html"))
                    .toList();

            for (Path template : templates) {
                String content = Files.readString(template);
                assertThat(content)
                        .withFailMessage("Plantilla %s contiene th:utext prohibido por CONSTITUTION regla 5", template.getFileName())
                        .doesNotContain("th:utext");
            }
        }
    }
}
