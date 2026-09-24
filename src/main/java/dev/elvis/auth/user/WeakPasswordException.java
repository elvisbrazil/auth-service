package dev.elvis.auth.user;

import java.util.List;

public class WeakPasswordException extends RuntimeException {

    private final List<String> violations;

    public WeakPasswordException(List<String> violations) {
        super("Password does not meet the policy");
        this.violations = List.copyOf(violations);
    }

    public List<String> violations() {
        return violations;
    }
}
