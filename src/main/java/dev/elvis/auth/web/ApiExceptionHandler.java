package dev.elvis.auth.web;

import dev.elvis.auth.auth.InvalidCredentialsException;
import dev.elvis.auth.token.InvalidRefreshTokenException;
import dev.elvis.auth.user.EmailAlreadyRegisteredException;
import dev.elvis.auth.user.WeakPasswordException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@RestControllerAdvice
public class ApiExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler
    ProblemDetail handle(EmailAlreadyRegisteredException ex) {
        var problem = ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, "Email is already registered");
        problem.setTitle("Email already registered");
        return problem;
    }

    @ExceptionHandler
    ProblemDetail handle(WeakPasswordException ex) {
        var problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        problem.setTitle("Weak password");
        problem.setProperty("violations", ex.violations());
        return problem;
    }

    @ExceptionHandler
    ProblemDetail handle(InvalidCredentialsException ex) {
        var problem = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, ex.getMessage());
        problem.setTitle("Invalid credentials");
        return problem;
    }

    @ExceptionHandler
    ProblemDetail handle(InvalidRefreshTokenException ex) {
        var problem = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, ex.getMessage());
        problem.setTitle("Invalid refresh token");
        return problem;
    }
}
