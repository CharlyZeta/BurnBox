package com.burnbox;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.modulith.core.ApplicationModules;

class ModularityTest {

    @Test
    @DisplayName("BR-002 / AC-003: Verifica fronteras estrictas de Spring Modulith")
    void verifiesModularStructure() {
        ApplicationModules.of(BurnboxApplication.class).verify();
    }
}
