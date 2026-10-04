package dev.elvis.auth.token;

import dev.elvis.auth.user.User;
import java.time.Clock;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RefreshTokenService {

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
        if (current.isUsed() || current.isRevoked() || current.isExpiredAt(now)) {
            throw new InvalidRefreshTokenException();
        }
        current.markUsed(now);
        var next = issue(current.getUser(), current.getFamilyId());
        return new RefreshRotation(current.getUser(), next);
    }

    private IssuedRefreshToken issue(User user, UUID familyId) {
        var now = clock.instant();
        var raw = TokenHashing.newOpaqueToken();
        var expiresAt = now.plus(properties.ttl());
        tokens.save(new RefreshToken(user, familyId, TokenHashing.sha256(raw), now, expiresAt));
        return new IssuedRefreshToken(raw, expiresAt);
    }
}
