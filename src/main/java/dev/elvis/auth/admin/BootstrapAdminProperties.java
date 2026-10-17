package dev.elvis.auth.admin;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("auth.bootstrap-admin")
public record BootstrapAdminProperties(String email, String password) {}
