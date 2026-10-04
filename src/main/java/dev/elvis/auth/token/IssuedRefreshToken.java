package dev.elvis.auth.token;

import java.time.Instant;

public record IssuedRefreshToken(String value, Instant expiresAt) {}
