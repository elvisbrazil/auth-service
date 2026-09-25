package dev.elvis.auth.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import org.junit.jupiter.api.Test;

class PasswordPolicyTest {

    private final PasswordPolicy policy = new PasswordPolicy();

    @Test
    void acceptsLongPasswordWithLettersAndDigits() {
        assertThat(policy.violations("ana@example.com", "correct-horse-42")).isEmpty();
    }

    @Test
    void rejectsShortPassword() {
        assertThat(policy.violations("ana@example.com", "abc123")).containsExactly("must have at least 10 characters");
    }

    @Test
    void rejectsPasswordLongerThanBcryptLimit() {
        var password = "a1".repeat(40);

        assertThat(policy.violations("ana@example.com", password)).containsExactly("must have at most 72 characters");
    }

    @Test
    void requiresLetterAndDigit() {
        assertThat(policy.violations("ana@example.com", "1234567890")).containsExactly("must contain a letter");
        assertThat(policy.violations("ana@example.com", "abcdefghij")).containsExactly("must contain a digit");
    }

    @Test
    void rejectsPasswordEqualToEmail() {
        assertThat(policy.violations("ana99@example.com", "ANA99@example.com"))
                .containsExactly("must not be the same as the email");
    }

    @Test
    void checkThrowsWithAllViolations() {
        assertThatExceptionOfType(WeakPasswordException.class)
                .isThrownBy(() -> policy.check("ana@example.com", "short"))
                .satisfies(ex -> assertThat(ex.violations()).hasSize(2));
    }
}
