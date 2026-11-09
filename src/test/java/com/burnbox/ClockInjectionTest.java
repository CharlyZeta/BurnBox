package com.burnbox;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.test.context.ActiveProfiles;

import java.time.Clock;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
class ClockInjectionTest {

    @Autowired
    private Clock clock;

    @Autowired
    private Environment environment;

    @Test
    @DisplayName("BR-001 / AF-01 / AC-008: Bean Clock inyectado y scheduler desactivado en perfil test")
    void clockIsInjectedAndSchedulerDisabled() {
        assertThat(clock).isNotNull();
        assertThat(environment.getProperty("burnbox.scheduler.enabled", Boolean.class)).isFalse();
    }
}
