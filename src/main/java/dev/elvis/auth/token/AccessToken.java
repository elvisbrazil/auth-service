package dev.elvis.auth.token;

import java.time.Duration;
import java.time.Instant;

public record AccessToken(String value, Instant issuedAt, Instant expiresAt) {

    public long expiresInSeconds() {
        return Duration.between(issuedAt, expiresAt).toSeconds();
    }
}
