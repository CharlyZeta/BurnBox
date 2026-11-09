package com.burnbox.secret;

import com.burnbox.crypto.CryptoTokenService;
import com.burnbox.crypto.LocalKeyProvider;
import com.burnbox.crypto.PassphraseKeyDeriver;
import com.burnbox.crypto.SecretEnvelopeService;
import com.burnbox.platform.DefaultSecurityEventPublisher;
import com.burnbox.platform.SecurityEventPublisher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class PassphraseProtectionTest {

    private static final Instant BASE_TIME = Instant.parse("2026-11-09T12:00:00Z");

    private SecretRepository repository;
    private SecretEnvelopeService envelopeService;
    private CryptoTokenService tokenService;
    private LocalKeyProvider keyProvider;
    private SecurityEventPublisher securityEventPublisher;
    private ApplicationEventPublisher applicationEventPublisher;
    private Clock clock;
    private SecretService secretService;

    private final ConcurrentHashMap<String, Secret> inMemoryDb = new ConcurrentHashMap<>();

    @BeforeEach
    void setUp() {
        inMemoryDb.clear();
        clock = Clock.fixed(BASE_TIME, ZoneOffset.UTC);
        tokenService = new CryptoTokenService();
        keyProvider = new LocalKeyProvider();
        PassphraseKeyDeriver keyDeriver = new PassphraseKeyDeriver();
        envelopeService = new SecretEnvelopeService(keyProvider, tokenService, keyDeriver);
        securityEventPublisher = mock(SecurityEventPublisher.class);
        applicationEventPublisher = mock(ApplicationEventPublisher.class);

        repository = mock(SecretRepository.class);

        when(repository.findByTokenHashForUpdate(anyString())).thenAnswer(invocation -> {
            String hash = invocation.getArgument(0);
            return Optional.ofNullable(inMemoryDb.get(hash));
        });

        doAnswer(invocation -> {
            Secret s = invocation.getArgument(0);
            inMemoryDb.put(s.tokenHash(), s);
            return null;
        }).when(repository).insert(any(Secret.class));

        doAnswer(invocation -> {
            UUID id = invocation.getArgument(0);
            int failed = invocation.getArgument(1);
            inMemoryDb.values().stream()
                    .filter(s -> s.id().equals(id))
                    .findFirst()
                    .ifPresent(existing -> {
                        Secret updated = new Secret(
                                existing.id(), existing.ownerUserId(), existing.tokenHash(),
                                existing.ciphertext(), existing.nonce(), existing.wrappedDek(),
                                existing.keyVersion(), existing.formatVersion(),
                                existing.passphraseSalt(), existing.passphraseProtected(),
                                existing.maxViews(), existing.views(), existing.state(),
                                existing.expiresAt(), existing.createdAt(), existing.consumedAt(),
                                failed, existing.recipientEmail(), existing.label()
                        );
                        inMemoryDb.put(updated.tokenHash(), updated);
                    });
            return null;
        }).when(repository).recordFailedAttempt(any(UUID.class), anyInt());

        doAnswer(invocation -> {
            UUID id = invocation.getArgument(0);
            int failed = invocation.getArgument(1);
            Instant destroyedAt = invocation.getArgument(2);
            inMemoryDb.values().stream()
                    .filter(s -> s.id().equals(id))
                    .findFirst()
                    .ifPresent(existing -> {
                        Secret destroyed = new Secret(
                                existing.id(), existing.ownerUserId(), existing.tokenHash(),
                                null, null, null,
                                existing.keyVersion(), existing.formatVersion(),
                                null, existing.passphraseProtected(),
                                existing.maxViews(), existing.views(), SecretState.DESTROYED_BY_ABUSE,
                                existing.expiresAt(), existing.createdAt(), destroyedAt,
                                failed, null, existing.label()
                        );
                        inMemoryDb.put(destroyed.tokenHash(), destroyed);
                    });
            return null;
        }).when(repository).destroyByAbuse(any(UUID.class), anyInt(), any(Instant.class));

        doAnswer(invocation -> {
            UUID id = invocation.getArgument(0);
            SecretState newState = invocation.getArgument(1);
            int views = invocation.getArgument(2);
            Instant consumedAt = invocation.getArgument(3);
            inMemoryDb.values().stream()
                    .filter(s -> s.id().equals(id))
                    .findFirst()
                    .ifPresent(existing -> {
                        byte[] cipher = newState.isTerminal() ? null : existing.ciphertext();
                        byte[] wrapped = newState.isTerminal() ? null : existing.wrappedDek();
                        byte[] salt = newState.isTerminal() ? null : existing.passphraseSalt();
                        Secret updated = new Secret(
                                existing.id(), existing.ownerUserId(), existing.tokenHash(),
                                cipher, existing.nonce(), wrapped,
                                existing.keyVersion(), existing.formatVersion(),
                                salt, existing.passphraseProtected(),
                                existing.maxViews(), views, newState,
                                existing.expiresAt(), existing.createdAt(), consumedAt,
                                existing.failedAttempts(), existing.recipientEmail(), existing.label()
                        );
                        inMemoryDb.put(updated.tokenHash(), updated);
                    });
            return null;
        }).when(repository).updateStateAndViews(any(UUID.class), any(SecretState.class), anyInt(), any());

        secretService = new SecretService(
                repository,
                envelopeService,
                tokenService,
                keyProvider,
                securityEventPublisher,
                applicationEventPublisher,
                clock
        );
    }

    @Test
    @DisplayName("Main Flow & AC-001, AC-003, AC-004: Passphrase-protected secret creation and reveal flow")
    void mainFlowPassphraseProtectedSecret() {
        byte[] payload = "Top-secret plan".getBytes(StandardCharsets.UTF_8);
        String passphrase = "my-strong-password";

        CreateSecretCommand cmd = new CreateSecretCommand(
                payload, Duration.ofHours(1), 1, UUID.randomUUID(), null, "Passphrase Secret", passphrase
        );

        CreateSecretResult created = secretService.createSecret(cmd);
        assertNotNull(created);

        // 1. Reveal without passphrase -> returns PassphraseRequired
        SecretAccessResult step1 = secretService.consumeSecret(created.tokenHash(), null);
        assertInstanceOf(SecretAccessResult.PassphraseRequired.class, step1);

        // 2. Reveal with correct passphrase -> reveals content successfully
        SecretAccessResult step2 = secretService.consumeSecret(created.tokenHash(), passphrase);
        assertInstanceOf(SecretAccessResult.Success.class, step2);
        SecretAccessResult.Success success = (SecretAccessResult.Success) step2;
        assertArrayEquals(payload, success.plaintext());
        assertEquals(SecretState.CONSUMED, success.state());
    }

    @Test
    @DisplayName("BR-001 & AC-002: Passphrase length validation rejects < 8 or > 128 chars")
    void passphraseLengthValidation() {
        byte[] payload = "Payload".getBytes(StandardCharsets.UTF_8);

        // < 8 chars
        IllegalArgumentException exShort = assertThrows(IllegalArgumentException.class, () ->
                new CreateSecretCommand(payload, Duration.ofHours(1), 1, null, null, null, "1234567")
        );
        assertTrue(exShort.getMessage().contains("between 8 and 128"));

        // > 128 chars
        String longPass = "a".repeat(129);
        IllegalArgumentException exLong = assertThrows(IllegalArgumentException.class, () ->
                new CreateSecretCommand(payload, Duration.ofHours(1), 1, null, null, null, longPass)
        );
        assertTrue(exLong.getMessage().contains("between 8 and 128"));
    }

    @Test
    @DisplayName("AF-01 & AC-005: Incorrect passphrase increments failed_attempts and returns WrongPassphrase")
    void wrongPassphraseIncrementsFailedAttempts() {
        byte[] payload = "Confidential memo".getBytes(StandardCharsets.UTF_8);
        CreateSecretCommand cmd = new CreateSecretCommand(
                payload, Duration.ofHours(1), 1, null, null, null, "correct-password-1"
        );
        CreateSecretResult created = secretService.createSecret(cmd);

        // First failure -> 4 remaining
        SecretAccessResult r1 = secretService.consumeSecret(created.tokenHash(), "wrong-password-1");
        assertInstanceOf(SecretAccessResult.WrongPassphrase.class, r1);
        assertEquals(4, ((SecretAccessResult.WrongPassphrase) r1).remainingAttempts());

        // Second failure -> 3 remaining
        SecretAccessResult r2 = secretService.consumeSecret(created.tokenHash(), "wrong-password-2");
        assertInstanceOf(SecretAccessResult.WrongPassphrase.class, r2);
        assertEquals(3, ((SecretAccessResult.WrongPassphrase) r2).remainingAttempts());

        verify(applicationEventPublisher, times(2)).publishEvent(any(PassphraseFailed.class));
    }

    @Test
    @DisplayName("AF-02, BR-005, AC-006 & AC-007: 5th failed passphrase destroys secret and emits event")
    void fifthFailedAttemptDestroysSecretIrreversibly() {
        byte[] payload = "Self-destruct data".getBytes(StandardCharsets.UTF_8);
        CreateSecretCommand cmd = new CreateSecretCommand(
                payload, Duration.ofHours(1), 1, null, null, null, "master-key-pass"
        );
        CreateSecretResult created = secretService.createSecret(cmd);

        // 4 failed attempts
        for (int i = 1; i <= 4; i++) {
            SecretAccessResult r = secretService.consumeSecret(created.tokenHash(), "bad-attempt-" + i);
            assertInstanceOf(SecretAccessResult.WrongPassphrase.class, r);
        }

        // 5th failed attempt -> Self-destruct!
        SecretAccessResult r5 = secretService.consumeSecret(created.tokenHash(), "bad-attempt-5");
        assertInstanceOf(SecretAccessResult.NotAvailable.class, r5);

        // Verify Secret is destroyed and content is purged
        Secret destroyed = inMemoryDb.get(created.tokenHash());
        assertEquals(SecretState.DESTROYED_BY_ABUSE, destroyed.state());
        assertNull(destroyed.ciphertext(), "Ciphertext must be wiped");
        assertNull(destroyed.wrappedDek(), "Wrapped DEK must be wiped");
        assertNull(destroyed.passphraseSalt(), "Salt must be wiped");

        // Verify domain event SecretDestroyedByAbuse was published
        ArgumentCaptor<SecretDestroyedByAbuse> captor = ArgumentCaptor.forClass(SecretDestroyedByAbuse.class);
        verify(applicationEventPublisher).publishEvent(captor.capture());
        assertEquals(destroyed.id(), captor.getValue().secretId());
        assertEquals(BASE_TIME, captor.getValue().destroyedAt());
    }

    @Test
    @DisplayName("FEAT-0008: Creación de secreto con contraseña y DefaultSecurityEventPublisher real no falla por validación de claves")
    void createSecretWithRealSecurityEventPublisherSucceeds() {
        DefaultSecurityEventPublisher realPublisher = new DefaultSecurityEventPublisher(applicationEventPublisher, clock);
        SecretService serviceWithRealPublisher = new SecretService(
                repository,
                envelopeService,
                tokenService,
                keyProvider,
                realPublisher,
                applicationEventPublisher,
                clock
        );

        CreateSecretCommand cmd = new CreateSecretCommand(
                "Super secret content".getBytes(StandardCharsets.UTF_8),
                Duration.ofHours(1),
                1,
                UUID.randomUUID(),
                null,
                "Test",
                "password-segura-123"
        );

        CreateSecretResult result = serviceWithRealPublisher.createSecret(cmd);
        assertNotNull(result);
        assertNotNull(result.secretId());
        assertNotNull(result.rawToken());
    }
}
