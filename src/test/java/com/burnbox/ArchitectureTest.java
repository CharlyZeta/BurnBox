package com.burnbox;

import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.lang.ArchRule;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

class ArchitectureTest {

    @Test
    @DisplayName("BR-001 / AC-006: Prohibido Instant.now() y LocalDateTime.now() fuera de ClockConfig")
    void noNowMethodsOutsideClockConfig() {
        ArchRule rule = noClasses()
                .that().doNotHaveFullyQualifiedName("com.burnbox.platform.ClockConfig")
                .should().callMethod(java.time.Instant.class, "now")
                .orShould().callMethod(java.time.LocalDateTime.class, "now")
                .orShould().callMethod(java.time.Clock.class, "systemUTC")
                .orShould().callMethod(java.time.Clock.class, "systemDefaultZone")
                .because("Todo el tiempo debe provenir de un bean Clock inyectado (CONSTITUTION regla 3)");

        rule.check(new ClassFileImporter().importPackages("com.burnbox"));
    }

    @Test
    @DisplayName("BR-003 / AC-007: Prohibido JPA y Hibernate")
    void noJpaOrHibernateAllowed() {
        ArchRule rule = noClasses()
                .should().dependOnClassesThat().resideInAnyPackage("jakarta.persistence..", "org.hibernate..")
                .because("La persistencia es exclusivamente SQL explícito con Spring Data JDBC y JdbcClient (CONSTITUTION regla 2)");

        rule.check(new ClassFileImporter().importPackages("com.burnbox"));
    }

    @Test
    @DisplayName("FEAT-0002 BR-001: Prohibido javax.crypto fuera de com.burnbox.crypto")
    void noCryptoOutsideCryptoModule() {
        ArchRule rule = noClasses()
                .that().resideOutsideOfPackage("com.burnbox.crypto..")
                .should().dependOnClassesThat().resideInAnyPackage("javax.crypto..")
                .because("Todo el código criptográfico vive en el módulo crypto (CONSTITUTION regla 1)");

        rule.check(new ClassFileImporter().importPackages("com.burnbox"));
    }
}
