package dev.elvis.auth.auth;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

@Component
public class LoginThrottle {

    private final Map<String, Attempts> attempts = new ConcurrentHashMap<>();
    private final LoginThrottleProperties properties;
    private final Clock clock;

    public LoginThrottle(LoginThrottleProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    public void checkAllowed(String email) {
        var now = clock.instant();
        var current = attempts.get(email);
        if (current != null && current.isLockedAt(now)) {
            throw new LoginLockedException(Duration.between(now, current.lockedUntil()));
        }
    }

    public void recordFailure(String email) {
        var now = clock.instant();
        attempts.compute(email, (key, current) -> {
            var failures = current == null || current.lockExpiredAt(now) ? 1 : current.failures() + 1;
            var lockedUntil = failures >= properties.maxFailures() ? now.plus(properties.lockDuration()) : null;
            return new Attempts(failures, lockedUntil);
        });
    }

    public void recordSuccess(String email) {
        attempts.remove(email);
    }

    private record Attempts(int failures, Instant lockedUntil) {

        boolean isLockedAt(Instant now) {
            return lockedUntil != null && now.isBefore(lockedUntil);
        }

        boolean lockExpiredAt(Instant now) {
            return lockedUntil != null && !now.isBefore(lockedUntil);
        }
    }
}
