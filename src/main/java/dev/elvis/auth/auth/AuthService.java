package dev.elvis.auth.auth;

import dev.elvis.auth.token.AccessTokenService;
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
    private final Clock clock;
    private final String dummyHash;

    public AuthService(
            UserRepository users, PasswordEncoder passwordEncoder, AccessTokenService accessTokens, Clock clock) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.accessTokens = accessTokens;
        this.clock = clock;
        this.dummyHash = passwordEncoder.encode("not-a-real-password-1");
    }

    @Transactional(readOnly = true)
    public TokenResponse login(String email, String password) {
        var user = users.findByEmail(email).orElse(null);
        if (user == null) {
            // burn the same bcrypt time so unknown emails can't be told apart by latency
            passwordEncoder.matches(password, dummyHash);
            throw new InvalidCredentialsException();
        }
        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new InvalidCredentialsException();
        }
        return tokensFor(user);
    }

    private TokenResponse tokensFor(User user) {
        var accessToken = accessTokens.issue(user);
        var expiresIn = Duration.between(clock.instant(), accessToken.expiresAt()).toSeconds();
        return new TokenResponse(accessToken.value(), "Bearer", expiresIn);
    }
}
