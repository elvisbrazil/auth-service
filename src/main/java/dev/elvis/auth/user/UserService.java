package dev.elvis.auth.user;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {

    private final UserRepository users;
    private final PasswordPolicy passwordPolicy;
    private final PasswordEncoder passwordEncoder;
    private final Clock clock;

    public UserService(
            UserRepository users, PasswordPolicy passwordPolicy, PasswordEncoder passwordEncoder, Clock clock) {
        this.users = users;
        this.passwordPolicy = passwordPolicy;
        this.passwordEncoder = passwordEncoder;
        this.clock = clock;
    }

    @Transactional
    public User register(String email, String password) {
        return create(email, password, Role.USER);
    }

    @Transactional
    public User create(String email, String password, Role role) {
        var normalizedEmail = normalize(email);
        passwordPolicy.check(normalizedEmail, password);
        if (users.existsByEmail(normalizedEmail)) {
            throw new EmailAlreadyRegisteredException(normalizedEmail);
        }
        var createdAt = clock.instant().truncatedTo(ChronoUnit.MICROS);
        var user = new User(normalizedEmail, passwordEncoder.encode(password), role, createdAt);
        return users.save(user);
    }

    public static String normalize(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }
}
