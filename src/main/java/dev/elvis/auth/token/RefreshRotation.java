package dev.elvis.auth.token;

import dev.elvis.auth.user.User;

public record RefreshRotation(User user, IssuedRefreshToken next) {}
