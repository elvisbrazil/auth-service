package dev.elvis.auth.token;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

@ConfigurationProperties("auth.jwt")
public record JwtProperties(String issuer, Duration accessTokenTtl, Resource publicKey, Resource privateKey) {

    boolean hasKeyPair() {
        return publicKey != null && privateKey != null;
    }
}
