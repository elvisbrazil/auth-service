package dev.elvis.auth.auth;

import dev.elvis.auth.token.AccessTokenService;
import dev.elvis.auth.token.IssuedRefreshToken;
import dev.elvis.auth.token.RefreshTokenService;
import dev.elvis.auth.user.User;
import dev.elvis.auth.user.UserRepository;
import java.time.Clock;
import java.time.Duration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final AccessTokenService accessTokens;
    private final RefreshTokenService refreshTokens;
    private final LoginThrottle throttle;
    private final Clock clock;
    private final String dummyHash;

    public AuthService(
            UserRepository users,
            PasswordEncoder passwordEncoder,
            AccessTokenService accessTokens,
            RefreshTokenService refreshTokens,
            LoginThrottle throttle,
            Clock clock) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.accessTokens = accessTokens;
        this.refreshTokens = refreshTokens;
        this.throttle = throttle;
        this.clock = clock;
        this.dummyHash = passwordEncoder.encode("not-a-real-password-1");
    }

    @Transactional
    public TokenResponse login(String email, String password) {
        throttle.checkAllowed(email);
        var user = users.findByEmail(email).orElse(null);
        if (user == null) {
            // burn the same bcrypt time so unknown emails can't be told apart by latency
            passwordEncoder.matches(password, dummyHash);
            throttle.recordFailure(email);
            throw new InvalidCredentialsException();
        }
        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            throttle.recordFailure(email);
            throw new InvalidCredentialsException();
        }
        throttle.recordSuccess(email);
        return tokensFor(user, refreshTokens.issue(user));
    }

    @Transactional
    public TokenResponse refresh(String refreshToken) {
        var rotation = refreshTokens.rotate(refreshToken);
        return tokensFor(rotation.user(), rotation.next());
    }

    public void logout(String refreshToken) {
        refreshTokens.revoke(refreshToken);
    }

    private TokenResponse tokensFor(User user, IssuedRefreshToken refreshToken) {
        var accessToken = accessTokens.issue(user);
        var expiresIn = Duration.between(clock.instant(), accessToken.expiresAt()).toSeconds();
        return new TokenResponse(accessToken.value(), "Bearer", expiresIn, refreshToken.value());
    }
}
