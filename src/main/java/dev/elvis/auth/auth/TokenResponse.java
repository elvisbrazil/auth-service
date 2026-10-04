package dev.elvis.auth.auth;

public record TokenResponse(String accessToken, String tokenType, long expiresIn, String refreshToken) {}
