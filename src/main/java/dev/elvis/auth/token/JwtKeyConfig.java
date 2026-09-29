package dev.elvis.auth.token;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.JOSEException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

@Configuration
class JwtKeyConfig {

    private static final Logger log = LoggerFactory.getLogger(JwtKeyConfig.class);

    @Bean
    RSAKey signingKey(JwtProperties properties) {
        if (properties.hasKeyPair()) {
            var publicKey = read(properties.publicKey(), RsaKeyConverters.x509()::convert);
            var privateKey = read(properties.privateKey(), RsaKeyConverters.pkcs8()::convert);
            return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(keyId(publicKey)).build();
        }
        log.warn("No JWT key pair configured, generating an ephemeral one. Tokens will not survive a restart.");
        return generate();
    }

    @Bean
    JwtEncoder jwtEncoder(RSAKey signingKey) {
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(signingKey)));
    }

    @Bean
    JwtDecoder jwtDecoder(RSAKey signingKey, JwtProperties properties) throws JOSEException {
        var decoder = NimbusJwtDecoder.withPublicKey(signingKey.toRSAPublicKey()).build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(properties.issuer()));
        return decoder;
    }

    private static <T> T read(Resource resource, Function<InputStream, T> converter) {
        try (var in = resource.getInputStream()) {
            return converter.apply(in);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read key from " + resource, e);
        }
    }

    private static String keyId(RSAPublicKey publicKey) {
        try {
            return new RSAKey.Builder(publicKey).build().computeThumbprint().toString();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static RSAKey generate() {
        try {
            var generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            var keyPair = generator.generateKeyPair();
            return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                    .privateKey((RSAPrivateKey) keyPair.getPrivate())
                    .keyID(UUID.randomUUID().toString())
                    .build();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
