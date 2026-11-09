package com.burnbox.ops;

import net.javacrumbs.shedlock.core.LockProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

@SpringBootTest(properties = "management.server.port=")
@ActiveProfiles("test")
class JobSchedulerIntegrationTest {

    @Autowired
    private LockProvider lockProvider;

    @Autowired
    private ExpiredSecretPurgeJob expiredSecretPurgeJob;

    @Autowired
    private SessionCleanupJob sessionCleanupJob;

    @Autowired
    private TombstoneCleanupJob tombstoneCleanupJob;

    @Autowired
    private KeyReEnvelopeJob keyReEnvelopeJob;

    @Test
    @DisplayName("C-17 / ShedLock: LockProvider bean está presente en el ApplicationContext y las tareas programadas no arrojan NoSuchBeanDefinitionException")
    void scheduledJobsExecuteWithLockProviderWithoutException() {
        assertThat(lockProvider).isNotNull();

        assertDoesNotThrow(() -> expiredSecretPurgeJob.schedule());
        assertDoesNotThrow(() -> sessionCleanupJob.schedule());
        assertDoesNotThrow(() -> tombstoneCleanupJob.schedule());
        assertDoesNotThrow(() -> keyReEnvelopeJob.schedule());
    }
}
