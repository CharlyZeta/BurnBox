package com.burnbox.secret;

import java.util.UUID;

public record SecretDeletedByOwnerEvent(
        UUID secretId,
        String tokenHash,
        UUID ownerId
) {}
