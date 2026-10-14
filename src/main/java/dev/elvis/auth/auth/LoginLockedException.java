package dev.elvis.auth.auth;

import java.time.Duration;

public class LoginLockedException extends RuntimeException {

    private final Duration retryAfter;

    public LoginLockedException(Duration retryAfter) {
        super("Too many failed login attempts, try again later");
        this.retryAfter = retryAfter;
    }

    public Duration retryAfter() {
        return retryAfter;
    }
}
