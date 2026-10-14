package dev.elvis.auth.auth;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("auth.login-throttle")
public record LoginThrottleProperties(int maxFailures, Duration lockDuration) {}
