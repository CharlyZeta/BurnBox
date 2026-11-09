package com.burnbox.secret;

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
 * zero secrets left in terminal state (BR-003), and domain event emission.
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
        SecretEnvelope envelope = envelopeService.encrypt(cmd.plaintext(), secretId, activeKeyVersion);

        Secret secret = new Secret(
                secretId,
                cmd.ownerUserId(),
                tokenHash,
                envelope.ciphertext(),
                envelope.nonce(),
                envelope.wrappedDek(),
                envelope.keyVersion(),
                envelope.formatVersion(),
                null,
                false,
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
        securityEventPublisher.publish("SECRET_CREATED", "secret", secretId.toString(), Map.of("max_views", cmd.maxViews()));

        return new CreateSecretResult(secretId, rawToken, tokenHash, expiresAt);
    }

    @Transactional
    public SecretAccessResult consumeSecret(String tokenHash) {
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
            // AF-01 / BR-005: Transiciona inmediatamente a EXPIRED y vacía contenido sin requerir job de purga
            repository.updateStateAndViews(secret.id(), SecretState.EXPIRED, secret.views(), null);
            applicationEventPublisher.publishEvent(new SecretExpiredEvent(secret.id(), tokenHash, now));
            securityEventPublisher.publish("SECRET_EXPIRED", "secret", secret.id().toString(), Map.of());
            return new SecretAccessResult.NotAvailable("Secret expired");
        }

        if (secret.views() >= secret.maxViews()) {
            repository.updateStateAndViews(secret.id(), SecretState.CONSUMED, secret.views(), now);
            return new SecretAccessResult.NotAvailable("Secret views exhausted");
        }

        int newViews = secret.views() + 1;
        SecretState newState = (newViews >= secret.maxViews()) ? SecretState.CONSUMED : SecretState.ACTIVE;
        Instant consumedAt = (newState == SecretState.CONSUMED) ? now : null;

        // BR-002 / BR-003: Actualiza vistas y si es terminal vacía columnas de contenido en la misma transacción
        repository.updateStateAndViews(secret.id(), newState, newViews, consumedAt);

        SecretEnvelope envelope = new SecretEnvelope(
                secret.ciphertext(),
                secret.nonce(),
                secret.wrappedDek(),
                secret.keyVersion(),
                secret.formatVersion()
        );

        byte[] plaintext = envelopeService.decrypt(envelope, secret.id());

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
