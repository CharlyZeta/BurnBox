package com.burnbox.secret;

import com.burnbox.crypto.CryptoException;
import com.burnbox.crypto.CryptoTokenService;
import com.burnbox.crypto.KeyProvider;
import com.burnbox.crypto.SecretEnvelope;
import com.burnbox.crypto.SecretEnvelopeService;
import com.burnbox.platform.SecurityEventPublisher;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Domain service managing the complete lifecycle of ephemeral secrets.
 * Enforces atomic consumption under SELECT FOR UPDATE (BR-004),
 * zero secrets left in terminal state (BR-003), passphrase protection (BR-001..BR-006),
 * and domain event emission.
 */
@Service
public class SecretService {

    private final SecretRepository repository;
    private final SecretEnvelopeService envelopeService;
    private final CryptoTokenService tokenService;
    private final KeyProvider keyProvider;
    private final SecurityEventPublisher securityEventPublisher;
    private final ApplicationEventPublisher applicationEventPublisher;
    private final Clock clock;

    public SecretService(
            SecretRepository repository,
            SecretEnvelopeService envelopeService,
            CryptoTokenService tokenService,
            KeyProvider keyProvider,
            SecurityEventPublisher securityEventPublisher,
            ApplicationEventPublisher applicationEventPublisher,
            Clock clock
    ) {
        this.repository = repository;
        this.envelopeService = envelopeService;
        this.tokenService = tokenService;
        this.keyProvider = keyProvider;
        this.securityEventPublisher = securityEventPublisher;
        this.applicationEventPublisher = applicationEventPublisher;
        this.clock = clock;
    }

    @Transactional
    public CreateSecretResult createSecret(CreateSecretCommand cmd) {
        UUID secretId = UUID.randomUUID();
        String rawToken = tokenService.generateToken();
        String tokenHash = tokenService.hashToken(rawToken);

        Instant now = Instant.now(clock);
        Instant expiresAt = now.plus(cmd.ttl());

        int activeKeyVersion = keyProvider.getActiveVersion();

        char[] passphraseChars = (cmd.passphrase() != null && !cmd.passphrase().isBlank())
                ? cmd.passphrase().toCharArray()
                : null;

        SecretEnvelopeService.EncryptionResult encResult = envelopeService.encrypt(
                cmd.plaintext(),
                secretId,
                activeKeyVersion,
                passphraseChars
        );
        SecretEnvelope envelope = encResult.envelope();
        byte[] salt = encResult.passphraseSalt();
        boolean hasPassphrase = (salt != null);

        Secret secret = new Secret(
                secretId,
                cmd.ownerUserId(),
                tokenHash,
                envelope.ciphertext(),
                envelope.nonce(),
                envelope.wrappedDek(),
                envelope.keyVersion(),
                envelope.formatVersion(),
                salt,
                hasPassphrase,
                cmd.maxViews(),
                0,
                SecretState.ACTIVE,
                expiresAt,
                now,
                null,
                0,
                cmd.recipientEmail(),
                cmd.label()
        );

        repository.insert(secret);

        applicationEventPublisher.publishEvent(new SecretCreatedEvent(secretId, tokenHash, expiresAt, cmd.maxViews()));
        securityEventPublisher.publish("SECRET_CREATED", "secret", secretId.toString(), Map.of(
                "max_views", cmd.maxViews(),
                "passphrase_protected", hasPassphrase
        ));

        return new CreateSecretResult(secretId, rawToken, tokenHash, expiresAt);
    }

    @Transactional(readOnly = true)
    public SecretAccessResult checkAccess(String tokenHash, String callerEmail, boolean callerEmailVerified) {
        if (tokenHash == null || tokenHash.isBlank()) {
            return new SecretAccessResult.NotAvailable("Invalid token hash");
        }

        Instant now = Instant.now(clock);
        Optional<Secret> optionalSecret = repository.findByTokenHash(tokenHash);

        if (optionalSecret.isEmpty()) {
            return new SecretAccessResult.NotAvailable("Secret not found or already consumed");
        }

        Secret secret = optionalSecret.get();

        if (secret.state().isTerminal() || secret.isExpired(now) || secret.views() >= secret.maxViews()) {
            return new SecretAccessResult.NotAvailable("Secret unavailable");
        }

        // BR-002, BR-003, BR-004: Restricción de destinatario
        if (secret.recipientEmail() != null && !secret.recipientEmail().isBlank()) {
            if (callerEmail == null || callerEmail.isBlank() || !callerEmailVerified) {
                return new SecretAccessResult.RecipientLoginRequired();
            }
            if (!secret.recipientEmail().equalsIgnoreCase(callerEmail.trim())) {
                securityEventPublisher.publish("SECRET_ACCESS_DENIED", "secret", secret.id().toString(), Map.of(
                        "reason", "recipient_mismatch"
                ));
                return new SecretAccessResult.NotAvailable("Secret unavailable");
            }
        }

        if (secret.passphraseProtected()) {
            return new SecretAccessResult.PassphraseRequired();
        }

        return new SecretAccessResult.Success(new byte[0], secret.views(), secret.maxViews(), secret.state());
    }

    @Transactional
    public SecretAccessResult consumeSecret(String tokenHash) {
        return consumeSecret(tokenHash, null, null, false);
    }

    @Transactional
    public SecretAccessResult consumeSecret(String tokenHash, String passphrase) {
        return consumeSecret(tokenHash, passphrase, null, false);
    }

    @Transactional
    public SecretAccessResult consumeSecret(String tokenHash, String passphrase, String callerEmail, boolean callerEmailVerified) {
        if (tokenHash == null || tokenHash.isBlank()) {
            return new SecretAccessResult.NotAvailable("Invalid token hash");
        }

        Instant now = Instant.now(clock);
        Optional<Secret> optionalSecret = repository.findByTokenHashForUpdate(tokenHash);

        if (optionalSecret.isEmpty()) {
            return new SecretAccessResult.NotAvailable("Secret not found or already consumed");
        }

        Secret secret = optionalSecret.get();

        if (secret.state().isTerminal()) {
            return new SecretAccessResult.NotAvailable("Secret in terminal state");
        }

        if (secret.isExpired(now)) {
            repository.updateStateAndViews(secret.id(), SecretState.EXPIRED, secret.views(), null);
            applicationEventPublisher.publishEvent(new SecretExpiredEvent(secret.id(), tokenHash, now));
            securityEventPublisher.publish("SECRET_EXPIRED", "secret", secret.id().toString(), Map.of());
            return new SecretAccessResult.NotAvailable("Secret expired");
        }

        if (secret.views() >= secret.maxViews()) {
            repository.updateStateAndViews(secret.id(), SecretState.CONSUMED, secret.views(), now);
            return new SecretAccessResult.NotAvailable("Secret views exhausted");
        }

        // BR-002, BR-003, BR-004: Restricción de destinatario
        if (secret.recipientEmail() != null && !secret.recipientEmail().isBlank()) {
            if (callerEmail == null || callerEmail.isBlank() || !callerEmailVerified) {
                securityEventPublisher.publish("SECRET_ACCESS_DENIED", "secret", secret.id().toString(), Map.of(
                        "reason", "unauthenticated_recipient"
                ));
                return new SecretAccessResult.RecipientLoginRequired();
            }
            if (!secret.recipientEmail().equalsIgnoreCase(callerEmail.trim())) {
                securityEventPublisher.publish("SECRET_ACCESS_DENIED", "secret", secret.id().toString(), Map.of(
                        "reason", "recipient_mismatch"
                ));
                return new SecretAccessResult.NotAvailable("Secret unavailable");
            }
        }

        // Passphrase handling
        if (secret.passphraseProtected()) {
            if (passphrase == null || passphrase.isBlank()) {
                // AC-003: Passphrase required to reveal
                return new SecretAccessResult.PassphraseRequired();
            }

            SecretEnvelope envelope = new SecretEnvelope(
                    secret.ciphertext(),
                    secret.nonce(),
                    secret.wrappedDek(),
                    secret.keyVersion(),
                    secret.formatVersion()
            );

            byte[] plaintext;
            try {
                plaintext = envelopeService.decrypt(
                        envelope,
                        secret.id(),
                        passphrase.toCharArray(),
                        secret.passphraseSalt()
                );
            } catch (CryptoException e) {
                // Passphrase failed
                int failedAttempts = secret.failedAttempts() + 1;
                if (failedAttempts >= 5) {
                    // BR-005 / AC-006 / AC-007: Quinto fallo destruye irreversiblemente
                    repository.destroyByAbuse(secret.id(), failedAttempts, now);
                    applicationEventPublisher.publishEvent(new SecretDestroyedByAbuse(
                            secret.id(),
                            now,
                            "Destroyed due to 5 consecutive failed passphrase attempts"
                    ));
                    securityEventPublisher.publish("SECRET_DESTROYED_BY_ABUSE", "secret", secret.id().toString(), Map.of(
                            "failed_attempts", failedAttempts
                    ));
                    return new SecretAccessResult.NotAvailable("Secret destroyed after 5 failed attempts");
                } else {
                    // AF-01 / AC-005: Increment failed attempts and return remaining
                    repository.recordFailedAttempt(secret.id(), failedAttempts);
                    int remaining = 5 - failedAttempts;
                    applicationEventPublisher.publishEvent(new PassphraseFailed(
                            secret.id(),
                            failedAttempts,
                            remaining,
                            now
                    ));
                    securityEventPublisher.publish("PASSPHRASE_FAILED", "secret", secret.id().toString(), Map.of(
                            "failed_attempts", failedAttempts,
                            "remaining_attempts", remaining
                    ));
                    return new SecretAccessResult.WrongPassphrase(remaining);
                }
            }

            return completeConsumption(secret, plaintext, tokenHash, now);
        } else {
            // Unprotected secret
            SecretEnvelope envelope = new SecretEnvelope(
                    secret.ciphertext(),
                    secret.nonce(),
                    secret.wrappedDek(),
                    secret.keyVersion(),
                    secret.formatVersion()
            );
            byte[] plaintext = envelopeService.decrypt(envelope, secret.id());
            return completeConsumption(secret, plaintext, tokenHash, now);
        }
    }

    private SecretAccessResult completeConsumption(Secret secret, byte[] plaintext, String tokenHash, Instant now) {
        int newViews = secret.views() + 1;
        SecretState newState = (newViews >= secret.maxViews()) ? SecretState.CONSUMED : SecretState.ACTIVE;
        Instant consumedAt = (newState == SecretState.CONSUMED) ? now : null;

        repository.updateStateAndViews(secret.id(), newState, newViews, consumedAt);

        applicationEventPublisher.publishEvent(new SecretRevealedEvent(secret.id(), tokenHash, newViews, secret.maxViews()));
        securityEventPublisher.publish("SECRET_REVEALED", "secret", secret.id().toString(), Map.of("view_number", newViews));

        if (newState == SecretState.CONSUMED) {
            applicationEventPublisher.publishEvent(new SecretConsumedEvent(secret.id(), tokenHash, consumedAt));
            securityEventPublisher.publish("SECRET_CONSUMED", "secret", secret.id().toString(), Map.of());
        }

        return new SecretAccessResult.Success(plaintext, newViews, secret.maxViews(), newState);
    }

    @Transactional
    public boolean deleteByOwner(UUID secretId, UUID ownerUserId) {
        Optional<Secret> opt = repository.findById(secretId);
        if (opt.isEmpty()) {
            return false;
        }

        Secret secret = opt.get();
        if (secret.state().isTerminal()) {
            return false;
        }

        if (ownerUserId != null && !ownerUserId.equals(secret.ownerUserId())) {
            return false;
        }

        repository.updateStateAndViews(secretId, SecretState.DELETED_BY_OWNER, secret.views(), null);
        applicationEventPublisher.publishEvent(new SecretDeletedByOwnerEvent(secretId, secret.tokenHash(), ownerUserId));
        securityEventPublisher.publish("SECRET_DELETED_BY_OWNER", "secret", secretId.toString(), Map.of());
        return true;
    }
}
