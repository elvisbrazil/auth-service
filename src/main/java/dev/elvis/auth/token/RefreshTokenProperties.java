package dev.elvis.auth.token;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("auth.refresh-token")
public record RefreshTokenProperties(Duration ttl) {}
