package com.burnbox.secret;

import java.util.UUID;

public record SecretRevealedEvent(
        UUID secretId,
        String tokenHash,
        int currentViews,
        int maxViews
) {}
