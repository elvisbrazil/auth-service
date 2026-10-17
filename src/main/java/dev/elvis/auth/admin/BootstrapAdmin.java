package dev.elvis.auth.admin;

import dev.elvis.auth.user.Role;
import dev.elvis.auth.user.UserRepository;
import dev.elvis.auth.user.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
class BootstrapAdmin implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(BootstrapAdmin.class);

    private final BootstrapAdminProperties properties;
    private final UserRepository users;
    private final UserService userService;

    BootstrapAdmin(BootstrapAdminProperties properties, UserRepository users, UserService userService) {
        this.properties = properties;
        this.users = users;
        this.userService = userService;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!StringUtils.hasText(properties.email())) {
            return;
        }
        var email = UserService.normalize(properties.email());
        if (users.existsByEmail(email)) {
            return;
        }
        userService.create(email, properties.password(), Role.ADMIN);
        log.info("Created bootstrap admin {}", email);
    }
}
