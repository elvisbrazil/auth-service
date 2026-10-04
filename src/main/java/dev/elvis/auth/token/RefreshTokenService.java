package dev.elvis.auth.token;

import dev.elvis.auth.user.User;
import java.time.Clock;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RefreshTokenService {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenService.class);

    private final RefreshTokenRepository tokens;
    private final RefreshTokenProperties properties;
    private final Clock clock;

    public RefreshTokenService(RefreshTokenRepository tokens, RefreshTokenProperties properties, Clock clock) {
        this.tokens = tokens;
        this.properties = properties;
        this.clock = clock;
    }

    @Transactional
    public IssuedRefreshToken issue(User user) {
        return issue(user, UUID.randomUUID());
    }

    @Transactional
    public RefreshRotation rotate(String rawToken) {
        var now = clock.instant();
        var current = tokens.findByTokenHash(TokenHashing.sha256(rawToken))
                .orElseThrow(InvalidRefreshTokenException::new);
        if (current.isUsed() || current.isRevoked()) {
            log.warn("Refresh token reuse detected, revoking family {}", current.getFamilyId());
            tokens.revokeFamily(current.getFamilyId(), now);
            throw new InvalidRefreshTokenException();
        }
        if (current.isExpiredAt(now)) {
            throw new InvalidRefreshTokenException();
        }
        current.markUsed(now);
        var next = issue(current.getUser(), current.getFamilyId());
        return new RefreshRotation(current.getUser(), next);
    }

    @Transactional
    public void revoke(String rawToken) {
        tokens.findByTokenHash(TokenHashing.sha256(rawToken))
                .ifPresent(token -> tokens.revokeFamily(token.getFamilyId(), clock.instant()));
    }

    private IssuedRefreshToken issue(User user, UUID familyId) {
        var now = clock.instant();
        var raw = TokenHashing.newOpaqueToken();
        var expiresAt = now.plus(properties.ttl());
        tokens.save(new RefreshToken(user, familyId, TokenHashing.sha256(raw), now, expiresAt));
        return new IssuedRefreshToken(raw, expiresAt);
    }
}
