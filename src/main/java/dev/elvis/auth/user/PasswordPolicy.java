package dev.elvis.auth.user;

import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Component;

@Component
public class PasswordPolicy {

    static final int MIN_LENGTH = 10;
    static final int MAX_LENGTH = 72;

    public List<String> violations(String email, String password) {
        var violations = new ArrayList<String>();
        if (password.length() < MIN_LENGTH) {
            violations.add("must have at least " + MIN_LENGTH + " characters");
        }
        if (password.length() > MAX_LENGTH) {
            violations.add("must have at most " + MAX_LENGTH + " characters");
        }
        if (password.chars().noneMatch(Character::isLetter)) {
            violations.add("must contain a letter");
        }
        if (password.chars().noneMatch(Character::isDigit)) {
            violations.add("must contain a digit");
        }
        if (password.equalsIgnoreCase(email)) {
            violations.add("must not be the same as the email");
        }
        return violations;
    }

    public void check(String email, String password) {
        var violations = violations(email, password);
        if (!violations.isEmpty()) {
            throw new WeakPasswordException(violations);
        }
    }
}
