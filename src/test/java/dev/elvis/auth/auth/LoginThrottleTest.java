package dev.elvis.auth.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import dev.elvis.auth.MutableClock;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class LoginThrottleTest {

    private static final String EMAIL = "ana@example.com";

    private final MutableClock clock = new MutableClock(Instant.parse("2026-10-10T10:00:00Z"));
    private final LoginThrottle throttle =
            new LoginThrottle(new LoginThrottleProperties(3, Duration.ofMinutes(15)), clock);

    @Test
    void allowsAttemptsBelowTheLimit() {
        fail(2);

        assertThatCode(() -> throttle.checkAllowed(EMAIL)).doesNotThrowAnyException();
    }

    @Test
    void locksAfterTooManyFailures() {
        fail(3);

        assertThatExceptionOfType(LoginLockedException.class)
                .isThrownBy(() -> throttle.checkAllowed(EMAIL))
                .satisfies(ex -> assertThat(ex.retryAfter()).isEqualTo(Duration.ofMinutes(15)));
    }

    @Test
    void lockExpiresAfterTheConfiguredDuration() {
        fail(3);
        clock.advance(Duration.ofMinutes(15));

        assertThatCode(() -> throttle.checkAllowed(EMAIL)).doesNotThrowAnyException();
    }

    @Test
    void failuresStartOverOnceTheLockExpires() {
        fail(3);
        clock.advance(Duration.ofMinutes(16));

        fail(2);

        assertThatCode(() -> throttle.checkAllowed(EMAIL)).doesNotThrowAnyException();
    }

    @Test
    void successfulLoginResetsTheCounter() {
        fail(2);
        throttle.recordSuccess(EMAIL);
        fail(2);

        assertThatCode(() -> throttle.checkAllowed(EMAIL)).doesNotThrowAnyException();
    }

    @Test
    void locksArePerEmail() {
        fail(3);

        assertThatCode(() -> throttle.checkAllowed("bruno@example.com")).doesNotThrowAnyException();
    }

    private void fail(int times) {
        for (int i = 0; i < times; i++) {
            throttle.recordFailure(EMAIL);
        }
    }
}
