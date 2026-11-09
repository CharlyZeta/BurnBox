package com.burnbox.ops;

import net.javacrumbs.shedlock.core.LockProvider;
import net.javacrumbs.shedlock.core.SimpleLock;
import net.javacrumbs.shedlock.provider.jdbctemplate.JdbcTemplateLockProvider;
import net.javacrumbs.shedlock.spring.annotation.EnableSchedulerLock;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.EnableScheduling;

import javax.sql.DataSource;
import java.util.Optional;

@Configuration(proxyBeanMethods = false)
@EnableScheduling
@EnableSchedulerLock(defaultLockAtMostFor = "PT10M")
public class ShedLockConfig {

    @Bean
    @Primary
    public LockProvider lockProvider(ObjectProvider<DataSource> dataSourceProvider) {
        DataSource dataSource = dataSourceProvider.getIfAvailable();
        if (dataSource != null) {
            return createJdbcLockProvider(dataSource);
        }
        return lockConfiguration -> Optional.of(new SimpleLock() {
            @Override
            public void unlock() {
                // No-op for standalone, in-memory or demo mode
            }
        });
    }

    public LockProvider lockProvider(DataSource dataSource) {
        return createJdbcLockProvider(dataSource);
    }

    private LockProvider createJdbcLockProvider(DataSource dataSource) {
        return new JdbcTemplateLockProvider(
                JdbcTemplateLockProvider.Configuration.builder()
                        .withJdbcTemplate(new JdbcTemplate(dataSource))
                        .usingDbTime()
                        .build()
        );
    }
}
