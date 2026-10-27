package dev.elvis.auth.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.elvis.auth.user.Role;
import dev.elvis.auth.user.User;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.security.oauth2.jwt.JwtException;

class AccessTokenServiceTest {

    private final Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    private final Clock clock = Clock.fixed(now, ZoneOffset.UTC);
    private final JwtProperties properties = new JwtProperties("auth-test", Duration.ofMinutes(15), null, null);
    private final JwtKeyConfig keyConfig = new JwtKeyConfig();
    private final User user = new User("ana@example.com", "hash", Role.ADMIN, now);

    @Test
    void issuesSignedTokenWithUserClaims() throws Exception {
        var key = keyConfig.signingKey(properties);
        var service = new AccessTokenService(keyConfig.jwtEncoder(key), properties, clock);

        var token = service.issue(user);
        var jwt = keyConfig.jwtDecoder(key, properties).decode(token.value());

        assertThat(jwt.getHeaders()).containsEntry("alg", "RS256");
        assertThat(jwt.getSubject()).isEqualTo(user.getId().toString());
        assertThat(jwt.getClaimAsString("iss")).isEqualTo("auth-test");
        assertThat(jwt.getClaimAsString("email")).isEqualTo("ana@example.com");
        assertThat(jwt.getClaimAsString("role")).isEqualTo("ADMIN");
        assertThat(jwt.getExpiresAt()).isEqualTo(now.plus(Duration.ofMinutes(15)));
        assertThat(token.expiresAt()).isEqualTo(jwt.getExpiresAt());
        assertThat(token.expiresInSeconds()).isEqualTo(900);
    }

    @Test
    void tokenSignedWithAnotherKeyIsRejected() throws Exception {
        var service = new AccessTokenService(keyConfig.jwtEncoder(keyConfig.signingKey(properties)), properties, clock);
        var otherDecoder = keyConfig.jwtDecoder(keyConfig.signingKey(properties), properties);

        var token = service.issue(user);

        assertThatThrownBy(() -> otherDecoder.decode(token.value())).isInstanceOf(JwtException.class);
    }

    @Test
    void tokenFromAnotherIssuerIsRejected() throws Exception {
        var key = keyConfig.signingKey(properties);
        var foreign = new JwtProperties("someone-else", Duration.ofMinutes(15), null, null);
        var service = new AccessTokenService(keyConfig.jwtEncoder(key), foreign, clock);

        var token = service.issue(user);

        assertThatThrownBy(() -> keyConfig.jwtDecoder(key, properties).decode(token.value()))
                .isInstanceOf(JwtException.class);
    }

    @Test
    void expiredTokenIsRejected() throws Exception {
        var key = keyConfig.signingKey(properties);
        var issuedAnHourAgo = Clock.fixed(now.minus(Duration.ofHours(1)), ZoneOffset.UTC);
        var service = new AccessTokenService(keyConfig.jwtEncoder(key), properties, issuedAnHourAgo);

        var token = service.issue(user);

        assertThatThrownBy(() -> keyConfig.jwtDecoder(key, properties).decode(token.value()))
                .isInstanceOf(JwtException.class)
                .hasMessageContaining("expired");
    }

    @Test
    void loadsConfiguredKeyPairFromPem() throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        var keyPair = generator.generateKeyPair();
        var configured = new JwtProperties(
                "auth-test",
                Duration.ofMinutes(15),
                pem("PUBLIC KEY", keyPair.getPublic().getEncoded()),
                pem("PRIVATE KEY", keyPair.getPrivate().getEncoded()));

        var key = keyConfig.signingKey(configured);

        assertThat(key.toRSAPublicKey()).isEqualTo(keyPair.getPublic());
        assertThat(key.toRSAPrivateKey()).isEqualTo(keyPair.getPrivate());
    }

    private static ByteArrayResource pem(String type, byte[] der) {
        var body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(der);
        var pem = "-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----\n";
        return new ByteArrayResource(pem.getBytes(StandardCharsets.US_ASCII));
    }
}
