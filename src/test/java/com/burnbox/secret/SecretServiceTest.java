package com.burnbox.secret;

import com.burnbox.crypto.CryptoTokenService;
import com.burnbox.crypto.LocalKeyProvider;
import com.burnbox.crypto.SecretEnvelopeService;
import com.burnbox.platform.SecurityEventPublisher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.context.ApplicationEventPublisher;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;

class SecretServiceTest {

    private final Instant baseTime = Instant.parse("2026-11-09T10:00:00Z");
    private MutableClock clock;
    private LocalKeyProvider keyProvider;
    private CryptoTokenService tokenService;
    private SecretEnvelopeService envelopeService;
    private SecurityEventPublisher securityEventPublisher;
    private ApplicationEventPublisher eventPublisher;
    private InMemorySecretRepository repository;
    private SecretService secretService;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(baseTime);
        keyProvider = new LocalKeyProvider();
        tokenService = new CryptoTokenService();
        envelopeService = new SecretEnvelopeService(keyProvider, tokenService);
        securityEventPublisher = Mockito.mock(SecurityEventPublisher.class);
        eventPublisher = Mockito.mock(ApplicationEventPublisher.class);
        repository = new InMemorySecretRepository();

        secretService = new SecretService(
                repository,
                envelopeService,
                tokenService,
                keyProvider,
                securityEventPublisher,
                eventPublisher,
                clock
        );
    }

    @Test
    @DisplayName("AC-001 / BR-001: Crear secreto persiste fila en ACTIVE con views=0 y contenido cifrado")
    void createSecretPersistsActiveWithZeroViews() {
        byte[] plaintext = "SecretPasswordToProtect".getBytes(StandardCharsets.UTF_8);
        CreateSecretCommand cmd = new CreateSecretCommand(plaintext, Duration.ofMinutes(15), 1, UUID.randomUUID(), null, "test-label");

        CreateSecretResult result = secretService.createSecret(cmd);

        assertThat(result.secretId()).isNotNull();
        assertThat(result.rawToken()).hasSize(43);
        assertThat(result.tokenHash()).hasSize(64);
        assertThat(result.expiresAt()).isEqualTo(baseTime.plus(Duration.ofMinutes(15)));

        Secret stored = repository.findById(result.secretId()).orElseThrow();
        assertThat(stored.state()).isEqualTo(SecretState.ACTIVE);
        assertThat(stored.views()).isEqualTo(0);
        assertThat(stored.maxViews()).isEqualTo(1);
        assertThat(stored.ciphertext()).isNotEmpty();
        assertThat(stored.wrappedDek()).isNotEmpty();
        assertThat(stored.nonce()).isNotEmpty();

        verify(eventPublisher).publishEvent(any(SecretCreatedEvent.class));
    }

    @Test
    @DisplayName("AC-002 / BR-002 / BR-003: Consumo de secreto con max_views=1 devuelve contenido, transiciona a CONSUMED y vacía ciphertext")
    void consumeSingleViewSecretSucceedsAndEmptiesContent() {
        byte[] plaintext = "OneTimeSecretText".getBytes(StandardCharsets.UTF_8);
        CreateSecretResult created = secretService.createSecret(new CreateSecretCommand(plaintext, Duration.ofMinutes(10), 1, null, null, null));

        SecretAccessResult accessResult = secretService.consumeSecret(created.tokenHash());

        assertThat(accessResult).isInstanceOf(SecretAccessResult.Success.class);
        SecretAccessResult.Success success = (SecretAccessResult.Success) accessResult;
        assertThat(new String(success.plaintext(), StandardCharsets.UTF_8)).isEqualTo("OneTimeSecretText");
        assertThat(success.views()).isEqualTo(1);
        assertThat(success.maxViews()).isEqualTo(1);
        assertThat(success.state()).isEqualTo(SecretState.CONSUMED);

        // Validar persistencia: columnas sensibles deben ser nulas en estado terminal (BR-003 / AC-007)
        Secret stored = repository.findById(created.secretId()).orElseThrow();
        assertThat(stored.state()).isEqualTo(SecretState.CONSUMED);
        assertThat(stored.views()).isEqualTo(1);
        assertThat(stored.ciphertext()).isNull();
        assertThat(stored.wrappedDek()).isNull();
        assertThat(stored.consumedAt()).isEqualTo(baseTime);

        verify(eventPublisher).publishEvent(any(SecretConsumedEvent.class));
    }

    @Test
    @DisplayName("AC-003 / AF-02: Segundo intento de consumo sobre secreto ya CONSUMED retorna NotAvailable")
    void secondConsumptionReturnsNotAvailable() {
        byte[] plaintext = "AlreadyReadSecret".getBytes(StandardCharsets.UTF_8);
        CreateSecretResult created = secretService.createSecret(new CreateSecretCommand(plaintext, Duration.ofMinutes(10), 1, null, null, null));

        secretService.consumeSecret(created.tokenHash());

        // Segundo intento
        SecretAccessResult secondAccess = secretService.consumeSecret(created.tokenHash());
        assertThat(secondAccess).isInstanceOf(SecretAccessResult.NotAvailable.class);

        Secret stored = repository.findById(created.secretId()).orElseThrow();
        assertThat(stored.views()).isEqualTo(1);
    }

    @Test
    @DisplayName("AC-004 / AF-03 / BR-004: Peticiones concurrentes con max_views=1 resultan en exactamente 1 éxito y N-1 NotAvailable")
    void concurrentConsumptionGuaranteesExactlyOneSuccess() throws Exception {
        byte[] plaintext = "ConcurrentSecretPayload".getBytes(StandardCharsets.UTF_8);
        CreateSecretResult created = secretService.createSecret(new CreateSecretCommand(plaintext, Duration.ofMinutes(10), 1, null, null, null));

        int threadCount = 20;
        ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);

        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger notAvailableCount = new AtomicInteger(0);

        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    SecretAccessResult result = secretService.consumeSecret(created.tokenHash());
                    if (result instanceof SecretAccessResult.Success) {
                        successCount.incrementAndGet();
                    } else if (result instanceof SecretAccessResult.NotAvailable) {
                        notAvailableCount.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        assertThat(doneLatch.await(5, TimeUnit.SECONDS)).isTrue();
        executor.shutdown();

        assertThat(successCount.get()).isEqualTo(1);
        assertThat(notAvailableCount.get()).isEqualTo(threadCount - 1);

        Secret stored = repository.findById(created.secretId()).orElseThrow();
        assertThat(stored.state()).isEqualTo(SecretState.CONSUMED);
        assertThat(stored.views()).isEqualTo(1);
        assertThat(stored.ciphertext()).isNull();
    }

    @Test
    @DisplayName("AC-005 / AF-01 / BR-005: Secreto vencido por fecha transiciona a EXPIRED, vacía ciphertext y retorna NotAvailable")
    void expiredSecretTransitionsToExpiredAndEmptiesContent() {
        byte[] plaintext = "ExpiredSecretText".getBytes(StandardCharsets.UTF_8);
        CreateSecretResult created = secretService.createSecret(new CreateSecretCommand(plaintext, Duration.ofMinutes(5), 1, null, null, null));

        // Avanzar el reloj 6 minutos
        clock.advance(Duration.ofMinutes(6));

        SecretAccessResult result = secretService.consumeSecret(created.tokenHash());
        assertThat(result).isInstanceOf(SecretAccessResult.NotAvailable.class);

        Secret stored = repository.findById(created.secretId()).orElseThrow();
        assertThat(stored.state()).isEqualTo(SecretState.EXPIRED);
        assertThat(stored.ciphertext()).isNull();
        assertThat(stored.wrappedDek()).isNull();

        verify(eventPublisher).publishEvent(any(SecretExpiredEvent.class));
    }

    @Test
    @DisplayName("AC-006 / AF-04: Secreto con max_views=2 permite primer consumo manteniendo estado ACTIVE y views=1")
    void multiViewSecretMaintainsActiveOnFirstView() {
        byte[] plaintext = "MultiViewSecretContent".getBytes(StandardCharsets.UTF_8);
        CreateSecretResult created = secretService.createSecret(new CreateSecretCommand(plaintext, Duration.ofMinutes(10), 2, null, null, null));

        // Primera lectura
        SecretAccessResult firstAccess = secretService.consumeSecret(created.tokenHash());
        assertThat(firstAccess).isInstanceOf(SecretAccessResult.Success.class);
        SecretAccessResult.Success s1 = (SecretAccessResult.Success) firstAccess;
        assertThat(s1.views()).isEqualTo(1);
        assertThat(s1.state()).isEqualTo(SecretState.ACTIVE);

        Secret afterFirst = repository.findById(created.secretId()).orElseThrow();
        assertThat(afterFirst.state()).isEqualTo(SecretState.ACTIVE);
        assertThat(afterFirst.views()).isEqualTo(1);
        assertThat(afterFirst.ciphertext()).isNotNull(); // Aún disponible

        // Segunda lectura
        SecretAccessResult secondAccess = secretService.consumeSecret(created.tokenHash());
        assertThat(secondAccess).isInstanceOf(SecretAccessResult.Success.class);
        SecretAccessResult.Success s2 = (SecretAccessResult.Success) secondAccess;
        assertThat(s2.views()).isEqualTo(2);
        assertThat(s2.state()).isEqualTo(SecretState.CONSUMED);

        Secret afterSecond = repository.findById(created.secretId()).orElseThrow();
        assertThat(afterSecond.state()).isEqualTo(SecretState.CONSUMED);
        assertThat(afterSecond.views()).isEqualTo(2);
        assertThat(afterSecond.ciphertext()).isNull(); // Ahora vaciado
    }

    @Test
    @DisplayName("AC-008 / AF-05: Propietario elimina secreto: transiciona a DELETED_BY_OWNER, vacía contenido y emite evento")
    void deleteByOwnerTransitionsToDeletedByOwner() {
        UUID ownerId = UUID.randomUUID();
        byte[] plaintext = "SecretToDelete".getBytes(StandardCharsets.UTF_8);
        CreateSecretResult created = secretService.createSecret(new CreateSecretCommand(plaintext, Duration.ofMinutes(15), 1, ownerId, null, null));

        boolean deleted = secretService.deleteByOwner(created.secretId(), ownerId);
        assertThat(deleted).isTrue();

        Secret stored = repository.findById(created.secretId()).orElseThrow();
        assertThat(stored.state()).isEqualTo(SecretState.DELETED_BY_OWNER);
        assertThat(stored.ciphertext()).isNull();

        verify(eventPublisher).publishEvent(any(SecretDeletedByOwnerEvent.class));
    }

    private static class MutableClock extends Clock {
        private Instant currentInstant;

        MutableClock(Instant initialInstant) {
            this.currentInstant = initialInstant;
        }

        void advance(Duration duration) {
            this.currentInstant = this.currentInstant.plus(duration);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return currentInstant;
        }
    }

    private static class InMemorySecretRepository extends SecretRepository {
        private final Map<UUID, Secret> byId = new ConcurrentHashMap<>();
        private final Map<String, UUID> byTokenHash = new ConcurrentHashMap<>();
        private final Map<UUID, ReentrantLock> locks = new ConcurrentHashMap<>();

        InMemorySecretRepository() {
            super(new org.springframework.beans.factory.support.StaticListableBeanFactory().getBeanProvider(org.springframework.jdbc.core.simple.JdbcClient.class));
        }

        @Override
        public void insert(Secret secret) {
            byId.put(secret.id(), secret);
            byTokenHash.put(secret.tokenHash(), secret.id());
            locks.put(secret.id(), new ReentrantLock());
        }

        @Override
        public Optional<Secret> findByTokenHashForUpdate(String tokenHash) {
            UUID id = byTokenHash.get(tokenHash);
            if (id == null) {
                return Optional.empty();
            }
            ReentrantLock lock = locks.computeIfAbsent(id, k -> new ReentrantLock());
            lock.lock();
            Secret secret = byId.get(id);
            if (secret == null || secret.state().isTerminal()) {
                lock.unlock();
            }
            return Optional.ofNullable(secret);
        }

        @Override
        public Optional<Secret> findById(UUID id) {
            return Optional.ofNullable(byId.get(id));
        }

        @Override
        public void updateStateAndViews(UUID id, SecretState newState, int views, Instant consumedAt) {
            ReentrantLock lock = locks.get(id);
            try {
                Secret existing = byId.get(id);
                if (existing != null) {
                    Secret updated = new Secret(
                            existing.id(),
                            existing.ownerUserId(),
                            existing.tokenHash(),
                            newState.isTerminal() ? null : existing.ciphertext(),
                            newState.isTerminal() ? null : existing.nonce(),
                            newState.isTerminal() ? null : existing.wrappedDek(),
                            existing.keyVersion(),
                            existing.formatVersion(),
                            newState.isTerminal() ? null : existing.passphraseSalt(),
                            existing.passphraseProtected(),
                            existing.maxViews(),
                            views,
                            newState,
                            existing.expiresAt(),
                            existing.createdAt(),
                            consumedAt != null ? consumedAt : existing.consumedAt(),
                            existing.failedAttempts(),
                            newState.isTerminal() ? null : existing.recipientEmail(),
                            existing.label()
                    );
                    byId.put(id, updated);
                }
            } finally {
                if (lock != null && lock.isHeldByCurrentThread()) {
                    lock.unlock();
                }
            }
        }
    }
}
