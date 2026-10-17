package dev.elvis.auth.admin;

import dev.elvis.auth.user.UserRepository;
import dev.elvis.auth.user.UserResponse;
import java.util.List;
import org.springframework.data.domain.Sort;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
public class AdminController {

    private final UserRepository users;

    public AdminController(UserRepository users) {
        this.users = users;
    }

    @GetMapping("/users")
    public List<UserResponse> users() {
        return users.findAll(Sort.by("createdAt")).stream()
                .map(UserResponse::from)
                .toList();
    }
}
