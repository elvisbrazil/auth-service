package dev.elvis.auth.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.elvis.auth.MutableClock;
import dev.elvis.auth.user.Role;
import dev.elvis.auth.user.User;
import dev.elvis.auth.user.UserRepository;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;

@DataJpaTest
@Import(RefreshTokenServiceTest.Config.class)
class RefreshTokenServiceTest {

    @TestConfiguration
    static class Config {

        @Bean
        @Primary
        MutableClock mutableClock() {
            return new MutableClock(Instant.parse("2026-10-01T12:00:00Z"));
        }

        @Bean
        RefreshTokenService refreshTokenService(RefreshTokenRepository tokens, MutableClock clock) {
            return new RefreshTokenService(tokens, new RefreshTokenProperties(Duration.ofDays(14)), clock);
        }
    }

    @Autowired
    RefreshTokenService service;

    @Autowired
    RefreshTokenRepository tokens;

    @Autowired
    UserRepository users;

    @Autowired
    MutableClock clock;

    User user;

    @BeforeEach
    void createUser() {
        user = users.save(new User("ana@example.com", "hash", Role.USER, clock.instant()));
    }

    @Test
    void storesOnlyTheHashOfTheToken() {
        var issued = service.issue(user);

        assertThat(tokens.findByTokenHash(issued.value())).isEmpty();
        assertThat(tokens.findByTokenHash(TokenHashing.sha256(issued.value()))).isPresent();
        assertThat(issued.expiresAt()).isEqualTo(clock.instant().plus(Duration.ofDays(14)));
    }

    @Test
    void rotationReplacesTokenWithinTheSameFamily() {
        var first = service.issue(user);

        var rotation = service.rotate(first.value());

        var old = tokens.findByTokenHash(TokenHashing.sha256(first.value())).orElseThrow();
        var next = tokens.findByTokenHash(TokenHashing.sha256(rotation.next().value())).orElseThrow();
        assertThat(rotation.user().getId()).isEqualTo(user.getId());
        assertThat(rotation.next().value()).isNotEqualTo(first.value());
        assertThat(old.getUsedAt()).isNotNull();
        assertThat(next.getFamilyId()).isEqualTo(old.getFamilyId());
        assertThat(next.getUsedAt()).isNull();
    }

    @Test
    void reusingRotatedTokenRevokesTheWholeFamily() {
        var first = service.issue(user);
        var second = service.rotate(first.value()).next();

        assertThatThrownBy(() -> service.rotate(first.value())).isInstanceOf(InvalidRefreshTokenException.class);

        assertThatThrownBy(() -> service.rotate(second.value())).isInstanceOf(InvalidRefreshTokenException.class);
        assertThat(tokens.findByTokenHash(TokenHashing.sha256(second.value())))
                .hasValueSatisfying(token -> assertThat(token.getRevokedAt()).isNotNull());
    }

    @Test
    void reuseDoesNotTouchOtherFamilies() {
        var stolen = service.issue(user);
        var otherDevice = service.issue(user);
        service.rotate(stolen.value());

        assertThatThrownBy(() -> service.rotate(stolen.value())).isInstanceOf(InvalidRefreshTokenException.class);

        assertThat(service.rotate(otherDevice.value()).user().getId()).isEqualTo(user.getId());
    }

    @Test
    void rejectsUnknownToken() {
        assertThatThrownBy(() -> service.rotate("does-not-exist")).isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test
    void rejectsExpiredToken() {
        var issued = service.issue(user);
        clock.advance(Duration.ofDays(14));

        assertThatThrownBy(() -> service.rotate(issued.value())).isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test
    void revokedFamilyCannotBeRefreshed() {
        var first = service.issue(user);
        var second = service.rotate(first.value()).next();

        service.revoke(second.value());

        assertThatThrownBy(() -> service.rotate(second.value())).isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test
    void revokingUnknownTokenIsIgnored() {
        service.revoke("does-not-exist");

        assertThat(tokens.count()).isZero();
    }
}
