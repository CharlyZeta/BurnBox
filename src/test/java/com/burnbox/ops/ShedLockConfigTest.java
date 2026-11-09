package com.burnbox.ops;

import net.javacrumbs.shedlock.core.LockProvider;
import net.javacrumbs.shedlock.spring.annotation.EnableSchedulerLock;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

import javax.sql.DataSource;
import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.DatabaseMetaData;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ShedLockConfigTest {

    @Test
    @DisplayName("AC-007 & AF-01: ShedLockConfig posee anotaciones @EnableScheduling y @EnableSchedulerLock")
    void shedLockConfigAnnotationsPresent() {
        assertThat(ShedLockConfig.class.isAnnotationPresent(EnableScheduling.class)).isTrue();
        assertThat(ShedLockConfig.class.isAnnotationPresent(EnableSchedulerLock.class)).isTrue();
    }

    @Test
    @DisplayName("AC-007: Crea LockProvider usando DataSource")
    void createsLockProviderFromDataSource() throws Exception {
        DataSource dataSource = mock(DataSource.class);
        Connection connection = mock(Connection.class);
        DatabaseMetaData metaData = mock(DatabaseMetaData.class);

        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.getMetaData()).thenReturn(metaData);
        when(metaData.getDatabaseProductName()).thenReturn("PostgreSQL");

        ShedLockConfig config = new ShedLockConfig();
        LockProvider provider = config.lockProvider(dataSource);

        assertThat(provider).isNotNull();
    }

    @Test
    @DisplayName("C-17 / Fallback: Provee fallback LockProvider sin errores cuando no hay DataSource")
    void createsFallbackLockProviderWhenDataSourceNotAvailable() {
        org.springframework.beans.factory.ObjectProvider<DataSource> emptyProvider = mock(org.springframework.beans.factory.ObjectProvider.class);
        when(emptyProvider.getIfAvailable()).thenReturn(null);

        ShedLockConfig config = new ShedLockConfig();
        LockProvider provider = config.lockProvider(emptyProvider);

        assertThat(provider).isNotNull();
        net.javacrumbs.shedlock.core.LockConfiguration lockConfig = new net.javacrumbs.shedlock.core.LockConfiguration(
                java.time.Instant.parse("2026-11-09T10:00:00Z"),
                "test-lock",
                java.time.Duration.ofMinutes(1),
                java.time.Duration.ZERO
        );
        java.util.Optional<net.javacrumbs.shedlock.core.SimpleLock> lock = provider.lock(lockConfig);
        assertThat(lock).isPresent();
        lock.get().unlock();
    }

    @Test
    @DisplayName("AC-007: Los jobs de higiene declaran anotación @SchedulerLock con nombre único y tiempo acotado")
    void jobsDeclareSchedulerLock() throws NoSuchMethodException {
        Method expiredMethod = ExpiredSecretPurgeJob.class.getMethod("schedule");
        SchedulerLock expiredLock = expiredMethod.getAnnotation(SchedulerLock.class);
        assertThat(expiredLock).isNotNull();
        assertThat(expiredLock.name()).isEqualTo("expired-secret-purge");
        assertThat(expiredMethod.isAnnotationPresent(Scheduled.class)).isTrue();

        Method tombstoneMethod = TombstoneCleanupJob.class.getMethod("schedule");
        SchedulerLock tombstoneLock = tombstoneMethod.getAnnotation(SchedulerLock.class);
        assertThat(tombstoneLock).isNotNull();
        assertThat(tombstoneLock.name()).isEqualTo("tombstone-cleanup");
        assertThat(tombstoneMethod.isAnnotationPresent(Scheduled.class)).isTrue();

        Method sessionMethod = SessionCleanupJob.class.getMethod("schedule");
        SchedulerLock sessionLock = sessionMethod.getAnnotation(SchedulerLock.class);
        assertThat(sessionLock).isNotNull();
        assertThat(sessionLock.name()).isEqualTo("session-cleanup");
        assertThat(sessionMethod.isAnnotationPresent(Scheduled.class)).isTrue();

        Method reEnvelopeMethod = KeyReEnvelopeJob.class.getMethod("schedule");
        SchedulerLock reEnvelopeLock = reEnvelopeMethod.getAnnotation(SchedulerLock.class);
        assertThat(reEnvelopeLock).isNotNull();
        assertThat(reEnvelopeLock.name()).isEqualTo("key-re-envelope");
        assertThat(reEnvelopeMethod.isAnnotationPresent(Scheduled.class)).isTrue();
    }
}
