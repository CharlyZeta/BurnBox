package com.burnbox.passkey;

import com.burnbox.platform.SecurityEventPublisher;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

@Service
public class PasskeyService {

    public static final Duration FIRST_PASSKEY_QUARANTINE = Duration.ofHours(24);

    private final PasskeyRepository repository;
    private final ApplicationEventPublisher applicationEventPublisher;
    private final SecurityEventPublisher securityEventPublisher;
    private final Clock clock;

    public PasskeyService(
            PasskeyRepository repository,
            ApplicationEventPublisher applicationEventPublisher,
            SecurityEventPublisher securityEventPublisher,
            Clock clock
    ) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.applicationEventPublisher = Objects.requireNonNull(applicationEventPublisher, "applicationEventPublisher must not be null");
        this.securityEventPublisher = Objects.requireNonNull(securityEventPublisher, "securityEventPublisher must not be null");
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    @Transactional
    public PasskeyCredential enrollPasskey(
            UUID userId,
            byte[] credentialId,
            byte[] publicKey,
            long initialSignCount,
            String transports,
            String label
    ) {
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(credentialId, "credentialId must not be null");
        Objects.requireNonNull(publicKey, "publicKey must not be null");
        Objects.requireNonNull(label, "label must not be null");

        Instant now = Instant.now(clock);
        int activeCount = repository.countActiveByUserId(userId);

        PasskeyState state;
        Instant activatesAt;

        if (activeCount == 0) {
            // BR-001: First passkey gets a 24-hour quarantine period
            state = PasskeyState.PENDING_ACTIVATION;
            activatesAt = now.plus(FIRST_PASSKEY_QUARANTINE);
        } else {
            // BR-002: Subsequent passkeys activate immediately
            state = PasskeyState.ACTIVE;
            activatesAt = null;
        }

        PasskeyCredential cred = new PasskeyCredential(
                UUID.randomUUID(),
                userId,
                credentialId,
                publicKey,
                initialSignCount,
                transports,
                label,
                state,
                activatesAt,
                now,
                null
        );

        repository.insertPasskey(cred);

        applicationEventPublisher.publishEvent(new PasskeyEnrolled(
                credentialId, userId, label, state, activatesAt, now
        ));

        String credHex = HexFormat.of().formatHex(credentialId);
        securityEventPublisher.publish("PASSKEY_ENROLLED", "passkey", credHex, Map.of(
                "userId", userId.toString(),
                "state", state.name(),
                "label", label
        ));

        if (state == PasskeyState.ACTIVE) {
            applicationEventPublisher.publishEvent(new PasskeyActivated(credentialId, userId, now));
            securityEventPublisher.publish("PASSKEY_ACTIVATED", "passkey", credHex, Map.of(
                    "userId", userId.toString()
            ));
        }

        return cred;
    }

    @Transactional
    public void activatePendingPasskey(UUID userId, byte[] credentialId) {
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(credentialId, "credentialId must not be null");
        Instant now = Instant.now(clock);

        PasskeyCredential cred = repository.findByCredentialId(credentialId)
                .orElseThrow(() -> new IllegalArgumentException("Credencial passkey no encontrada"));

        if (!cred.userId().equals(userId)) {
            throw new SecurityException("No tiene autorización sobre esta credencial");
        }

        if (cred.state() != PasskeyState.PENDING_ACTIVATION) {
            return;
        }

        // AF-02: Deny activation if quarantine has not elapsed
        if (now.isBefore(cred.activatesAt())) {
            throw new IllegalStateException("La credencial se encuentra en período de cuarentena de 24 horas hasta: " + cred.activatesAt());
        }

        repository.updateState(credentialId, PasskeyState.ACTIVE);

        applicationEventPublisher.publishEvent(new PasskeyActivated(credentialId, userId, now));
        String credHex = HexFormat.of().formatHex(credentialId);
        securityEventPublisher.publish("PASSKEY_ACTIVATED", "passkey", credHex, Map.of(
                "userId", userId.toString()
        ));
    }

    @Transactional
    public AssertionResult verifyAssertion(byte[] credentialId, long newSignCount) {
        Objects.requireNonNull(credentialId, "credentialId must not be null");
        Instant now = Instant.now(clock);

        Optional<PasskeyCredential> credOpt = repository.findByCredentialId(credentialId);
        if (credOpt.isEmpty()) {
            return AssertionResult.NOT_FOUND;
        }

        PasskeyCredential cred = credOpt.get();
        if (cred.state() != PasskeyState.ACTIVE) {
            return AssertionResult.NOT_ACTIVE;
        }

        // BR-003: Authenticator clone detection
        if (newSignCount <= cred.signCount() && !(newSignCount == 0 && cred.signCount() == 0)) {
            applicationEventPublisher.publishEvent(new PasskeyCounterAnomaly(
                    credentialId, cred.userId(), cred.signCount(), newSignCount, now
            ));
            String credHex = HexFormat.of().formatHex(credentialId);
            securityEventPublisher.publish("PASSKEY_COUNTER_ANOMALY", "passkey", credHex, Map.of(
                    "userId", cred.userId().toString(),
                    "previousSignCount", String.valueOf(cred.signCount()),
                    "reportedSignCount", String.valueOf(newSignCount)
            ));
            return AssertionResult.ANOMALY_DETECTED;
        }

        repository.updateSignCountAndLastUsed(credentialId, newSignCount, now);
        return AssertionResult.SUCCESS;
    }

    @Transactional
    public void revokePasskey(UUID userId, byte[] credentialId) {
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(credentialId, "credentialId must not be null");
        Instant now = Instant.now(clock);

        PasskeyCredential cred = repository.findByCredentialId(credentialId)
                .orElseThrow(() -> new IllegalArgumentException("Credencial passkey no encontrada"));

        if (!cred.userId().equals(userId)) {
            throw new SecurityException("No tiene autorización para revocar esta credencial");
        }

        repository.updateState(credentialId, PasskeyState.REVOKED);

        applicationEventPublisher.publishEvent(new PasskeyRevoked(credentialId, userId, now, "USER_MANUAL_REVOCATION"));
        String credHex = HexFormat.of().formatHex(credentialId);
        securityEventPublisher.publish("PASSKEY_REVOKED", "passkey", credHex, Map.of(
                "userId", userId.toString()
        ));
    }

    @Transactional(readOnly = true)
    public List<PasskeyCredential> listPasskeys(UUID userId) {
        Objects.requireNonNull(userId, "userId must not be null");
        return repository.findByUserId(userId);
    }
}
