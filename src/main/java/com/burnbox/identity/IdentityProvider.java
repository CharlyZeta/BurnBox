package com.burnbox.identity;

public enum IdentityProvider {
    GOOGLE,
    MICROSOFT;

    public static IdentityProvider fromRegistrationId(String registrationId) {
        if (registrationId == null) {
            throw new IllegalArgumentException("Registration ID cannot be null");
        }
        return switch (registrationId.trim().toLowerCase()) {
            case "google" -> GOOGLE;
            case "microsoft" -> MICROSOFT;
            default -> throw new IllegalArgumentException("Unsupported identity provider: " + registrationId);
        };
    }
}
