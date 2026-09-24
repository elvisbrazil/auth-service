package dev.elvis.auth.user;

public class EmailAlreadyRegisteredException extends RuntimeException {

    public EmailAlreadyRegisteredException(String email) {
        super("Email already registered: " + email);
    }
}
