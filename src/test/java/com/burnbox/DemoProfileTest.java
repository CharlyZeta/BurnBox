package com.burnbox;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(properties = {
        "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration,org.springframework.boot.autoconfigure.data.jdbc.JdbcRepositoriesAutoConfiguration,org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration",
        "management.server.port="
})
@ActiveProfiles("demo")
class DemoProfileTest {

    @Autowired
    private Environment environment;

    @Test
    @DisplayName("AF-03: Perfil demo acota TTL máximo a 1 hora y cuota de creación a 5 por hora")
    void demoProfileConfiguresBoundedLimits() {
        assertThat(environment.getProperty("burnbox.demo.enabled", Boolean.class)).isTrue();
        assertThat(environment.getProperty("burnbox.demo.max-ttl-hours", Integer.class)).isEqualTo(1);
        assertThat(environment.getProperty("burnbox.demo.create-rate-limit-per-hour", Integer.class)).isEqualTo(5);
    }
}
