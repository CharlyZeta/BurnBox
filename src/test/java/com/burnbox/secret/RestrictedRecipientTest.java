package com.burnbox.secret;

import com.burnbox.crypto.CryptoTokenService;
import com.burnbox.crypto.KeyProvider;
import com.burnbox.crypto.LocalKeyProvider;
import com.burnbox.crypto.PassphraseKeyDeriver;
import com.burnbox.crypto.SecretEnvelopeService;
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
import java.time.ZoneId;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class RestrictedRecipientTest {

    private SecretRepository repository;
    private SecretEnvelopeService envelopeService;
    private CryptoTokenService tokenService;
    private KeyProvider keyProvider;
    private SecurityEventPublisher securityEventPublisher;
    private ApplicationEventPublisher applicationEventPublisher;
    private Clock clock;
    private SecretService secretService;

    private final Instant baseTime = Instant.parse("2026-11-09T18:00:00Z");

    @BeforeEach
    void setUp() {
        repository = mock(SecretRepository.class);
        tokenService = new CryptoTokenService();
        keyProvider = new LocalKeyProvider();
        PassphraseKeyDeriver keyDeriver = new PassphraseKeyDeriver();
        envelopeService = new SecretEnvelopeService(keyProvider, tokenService, keyDeriver);
        securityEventPublisher = mock(SecurityEventPublisher.class);
        applicationEventPublisher = mock(ApplicationEventPublisher.class);
        clock = Clock.fixed(baseTime, ZoneId.of("UTC"));

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
    @DisplayName("AC-001 & BR-001: Crear secreto con email de destinatario válido persiste recipient_email normalizado")
    void createSecretWithValidRecipient() {
        UUID ownerId = UUID.randomUUID();
        CreateSecretCommand cmd = new CreateSecretCommand(
                "Super confidential data".getBytes(StandardCharsets.UTF_8),
                Duration.ofHours(1),
                1,
                ownerId,
                "  Alice.Smith@Example.COM  ",
                "Work note"
        );

        CreateSecretResult result = secretService.createSecret(cmd);
        assertThat(result).isNotNull();
        assertThat(result.rawToken()).hasSize(43);

        ArgumentCaptor<Secret> captor = ArgumentCaptor.forClass(Secret.class);
        verify(repository).insert(captor.capture());

        Secret saved = captor.getValue();
        assertThat(saved.recipientEmail()).isEqualTo("alice.smith@example.com");
    }

    @Test
    @DisplayName("AC-002 & BR-001 & AF-01: Crear secreto con email inválido es rechazado")
    void createSecretWithInvalidEmailThrows() {
        assertThatThrownBy(() -> new CreateSecretCommand(
                "Data".getBytes(StandardCharsets.UTF_8),
                Duration.ofHours(1),
                1,
                UUID.randomUUID(),
                "invalid-email-address",
                null
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("Invalid recipient email format");
    }

    @Test
    @DisplayName("AC-003 & BR-002: Visitante anónimo recibe RecipientLoginRequired en checkAccess")
    void anonymousCheckAccessRequiresLogin() {
        String token = tokenService.generateToken();
        String tokenHash = tokenService.hashToken(token);

        Secret secret = createSampleRestrictedSecret(tokenHash, "recipient@burnbox.io", false);
        when(repository.findByTokenHash(tokenHash)).thenReturn(Optional.of(secret));

        SecretAccessResult result = secretService.checkAccess(tokenHash, null, false);
        assertThat(result).isInstanceOf(SecretAccessResult.RecipientLoginRequired.class);
    }

    @Test
    @DisplayName("AC-004 & BR-003: Usuario con email coincidente y verificado pasa checkAccess")
    void matchingVerifiedUserPassesCheckAccess() {
        String token = tokenService.generateToken();
        String tokenHash = tokenService.hashToken(token);

        Secret secret = createSampleRestrictedSecret(tokenHash, "recipient@burnbox.io", false);
        when(repository.findByTokenHash(tokenHash)).thenReturn(Optional.of(secret));

        SecretAccessResult result = secretService.checkAccess(tokenHash, "recipient@burnbox.io", true);
        assertThat(result).isInstanceOf(SecretAccessResult.Success.class);
    }

    @Test
    @DisplayName("AC-005 & BR-004 & AF-03: Usuario con email diferente recibe NotAvailable y emite auditoría sin PII")
    void mismatchingUserReceivesNotAvailable() {
        String token = tokenService.generateToken();
        String tokenHash = tokenService.hashToken(token);

        Secret secret = createSampleRestrictedSecret(tokenHash, "recipient@burnbox.io", false);
        when(repository.findByTokenHash(tokenHash)).thenReturn(Optional.of(secret));

        SecretAccessResult result = secretService.checkAccess(tokenHash, "attacker@other.org", true);
        assertThat(result).isInstanceOf(SecretAccessResult.NotAvailable.class);

        // Verifica auditoría de intento denegado sin PII en details
        ArgumentCaptor<Map<String, Object>> detailsCaptor = ArgumentCaptor.forClass(Map.class);
        verify(securityEventPublisher).publish(
                eq("SECRET_ACCESS_DENIED"),
                eq("secret"),
                eq(secret.id().toString()),
                detailsCaptor.capture()
        );

        Map<String, Object> details = detailsCaptor.getValue();
        assertThat(details).containsEntry("reason", "recipient_mismatch");
        assertThat(details.values().toString()).doesNotContain("recipient@burnbox.io");
        assertThat(details.values().toString()).doesNotContain("attacker@other.org");
    }

    @Test
    @DisplayName("AC-006 & BR-003 & Main Flow: Destinatario con email coincidente revela el secreto exitosamente")
    void matchingRecipientRevealsSecretSuccessfully() {
        String rawContent = "Sensitive executive briefing";
        UUID secretId = UUID.randomUUID();
        String rawToken = tokenService.generateToken();
        String tokenHash = tokenService.hashToken(rawToken);

        SecretEnvelopeService.EncryptionResult enc = envelopeService.encrypt(
                rawContent.getBytes(StandardCharsets.UTF_8),
                secretId,
                1,
                null
        );

        Secret secret = new Secret(
                secretId,
                UUID.randomUUID(),
                tokenHash,
                enc.envelope().ciphertext(),
                enc.envelope().nonce(),
                enc.envelope().wrappedDek(),
                1,
                1,
                null,
                false,
                1,
                0,
                SecretState.ACTIVE,
                baseTime.plus(Duration.ofHours(1)),
                baseTime,
                null,
                0,
                "recipient@burnbox.io",
                null
        );

        when(repository.findByTokenHashForUpdate(tokenHash)).thenReturn(Optional.of(secret));

        SecretAccessResult result = secretService.consumeSecret(tokenHash, null, "recipient@burnbox.io", true);
        assertThat(result).isInstanceOf(SecretAccessResult.Success.class);

        SecretAccessResult.Success success = (SecretAccessResult.Success) result;
        assertThat(new String(success.plaintext(), StandardCharsets.UTF_8)).isEqualTo(rawContent);
        assertThat(success.state()).isEqualTo(SecretState.CONSUMED);
    }

    @Test
    @DisplayName("AC-007 & BR-005: Composición con Passphrase exige coincidencia de destinatario primero")
    void compositionWithPassphraseRequiresRecipientMatchFirst() {
        String rawContent = "Double wrapped classified note";
        UUID secretId = UUID.randomUUID();
        String rawToken = tokenService.generateToken();
        String tokenHash = tokenService.hashToken(rawToken);
        char[] passphrase = "strong-vault-passphrase".toCharArray();

        SecretEnvelopeService.EncryptionResult enc = envelopeService.encrypt(
                rawContent.getBytes(StandardCharsets.UTF_8),
                secretId,
                1,
                passphrase
        );

        Secret secret = new Secret(
                secretId,
                UUID.randomUUID(),
                tokenHash,
                enc.envelope().ciphertext(),
                enc.envelope().nonce(),
                enc.envelope().wrappedDek(),
                1,
                1,
                enc.passphraseSalt(),
                true,
                1,
                0,
                SecretState.ACTIVE,
                baseTime.plus(Duration.ofHours(1)),
                baseTime,
                null,
                0,
                "recipient@burnbox.io",
                null
        );

        when(repository.findByTokenHashForUpdate(tokenHash)).thenReturn(Optional.of(secret));

        // 1. Wrong user receives NotAvailable immediately, even if they have the password
        SecretAccessResult wrongUserResult = secretService.consumeSecret(tokenHash, "strong-vault-passphrase", "wrong@burnbox.io", true);
        assertThat(wrongUserResult).isInstanceOf(SecretAccessResult.NotAvailable.class);

        // 2. Right user without password receives PassphraseRequired
        SecretAccessResult noPassResult = secretService.consumeSecret(tokenHash, null, "recipient@burnbox.io", true);
        assertThat(noPassResult).isInstanceOf(SecretAccessResult.PassphraseRequired.class);

        // 3. Right user with wrong password receives WrongPassphrase
        SecretAccessResult wrongPassResult = secretService.consumeSecret(tokenHash, "wrong-password", "recipient@burnbox.io", true);
        assertThat(wrongPassResult).isInstanceOf(SecretAccessResult.WrongPassphrase.class);

        // 4. Right user with correct password succeeds
        SecretAccessResult successResult = secretService.consumeSecret(tokenHash, "strong-vault-passphrase", "recipient@burnbox.io", true);
        assertThat(successResult).isInstanceOf(SecretAccessResult.Success.class);
        assertThat(new String(((SecretAccessResult.Success) successResult).plaintext(), StandardCharsets.UTF_8)).isEqualTo(rawContent);
    }

    @Test
    @DisplayName("AC-008 & BR-006 & AF-04: Secreto en estado terminal responde NotAvailable genérico")
    void terminalSecretReturnsNotAvailable() {
        String token = tokenService.generateToken();
        String tokenHash = tokenService.hashToken(token);

        Secret terminalSecret = new Secret(
                UUID.randomUUID(),
                UUID.randomUUID(),
                tokenHash,
                null,
                null,
                null,
                1,
                1,
                null,
                false,
                1,
                1,
                SecretState.CONSUMED,
                baseTime.plus(Duration.ofHours(1)),
                baseTime.minus(Duration.ofMinutes(10)),
                baseTime,
                0,
                null,
                null
        );

        when(repository.findByTokenHash(tokenHash)).thenReturn(Optional.of(terminalSecret));
        when(repository.findByTokenHashForUpdate(tokenHash)).thenReturn(Optional.of(terminalSecret));

        SecretAccessResult getResult = secretService.checkAccess(tokenHash, "recipient@burnbox.io", true);
        assertThat(getResult).isInstanceOf(SecretAccessResult.NotAvailable.class);

        SecretAccessResult postResult = secretService.consumeSecret(tokenHash, null, "recipient@burnbox.io", true);
        assertThat(postResult).isInstanceOf(SecretAccessResult.NotAvailable.class);
    }

    private Secret createSampleRestrictedSecret(String tokenHash, String recipientEmail, boolean hasPassphrase) {
        return new Secret(
                UUID.randomUUID(),
                UUID.randomUUID(),
                tokenHash,
                new byte[]{1, 2, 3},
                new byte[]{4, 5, 6},
                new byte[]{7, 8, 9},
                1,
                1,
                hasPassphrase ? new byte[]{1, 2, 3, 4} : null,
                hasPassphrase,
                1,
                0,
                SecretState.ACTIVE,
                baseTime.plus(Duration.ofHours(1)),
                baseTime,
                null,
                0,
                recipientEmail,
                null
        );
    }
}
