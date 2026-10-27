package dev.elvis.auth.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.elvis.auth.user.Role;
import dev.elvis.auth.user.UserService;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

@SpringBootTest
@AutoConfigureMockMvc
class AuthFlowTest {

    private static final String PASSWORD = "correct-horse-42";

    @Autowired
    MockMvc mvc;

    @Autowired
    ObjectMapper json;

    @Autowired
    UserService userService;

    @Test
    void registerLoginRefreshAndLogout() throws Exception {
        register("flow@example.com", PASSWORD)
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value("flow@example.com"))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.passwordHash").doesNotExist());

        var tokens = login("flow@example.com", PASSWORD);
        assertThat(tokens.get("tokenType").asText()).isEqualTo("Bearer");
        assertThat(tokens.get("expiresIn").asLong()).isEqualTo(900);

        mvc.perform(get("/me").header(HttpHeaders.AUTHORIZATION, bearer(tokens)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("flow@example.com"));

        var refreshed = parse(refresh(tokens.get("refreshToken").asText()).andExpect(status().isOk()));
        assertThat(refreshed.get("refreshToken").asText())
                .isNotEqualTo(tokens.get("refreshToken").asText());

        mvc.perform(get("/me").header(HttpHeaders.AUTHORIZATION, bearer(refreshed)))
                .andExpect(status().isOk());

        mvc.perform(post("/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body(Map.of(
                                "refreshToken", refreshed.get("refreshToken").asText()))))
                .andExpect(status().isNoContent());

        refresh(refreshed.get("refreshToken").asText()).andExpect(status().isUnauthorized());
    }

    @Test
    void duplicateEmailIsRejectedWithConflict() throws Exception {
        register("dup@example.com", PASSWORD).andExpect(status().isCreated());

        register("Dup@Example.com", PASSWORD)
                .andExpect(status().isConflict())
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.title").value("Email already registered"));
    }

    @Test
    void weakPasswordIsRejectedWithViolations() throws Exception {
        register("weak@example.com", "password")
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.violations").value(hasItem("must contain a digit")));
    }

    @Test
    void malformedEmailIsRejected() throws Exception {
        register("not-an-email", PASSWORD)
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON));
    }

    @Test
    void wrongPasswordIsUnauthorized() throws Exception {
        register("wrong@example.com", PASSWORD);

        attemptLogin("wrong@example.com", "incorrect-horse-42")
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.title").value("Invalid credentials"));
    }

    @Test
    void unknownEmailLooksLikeWrongPassword() throws Exception {
        attemptLogin("nobody@example.com", PASSWORD)
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.title").value("Invalid credentials"));
    }

    @Test
    void meRequiresAccessToken() throws Exception {
        mvc.perform(get("/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("Bearer")))
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.status").value(401));
    }

    @Test
    void tamperedAccessTokenIsRejected() throws Exception {
        register("tamper@example.com", PASSWORD);
        var token = login("tamper@example.com", PASSWORD).get("accessToken").asText();
        var tampered = token.substring(0, token.length() - 4) + "AAAA";

        mvc.perform(get("/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + tampered))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON));
    }

    @Test
    void regularUserCannotListUsers() throws Exception {
        register("regular@example.com", PASSWORD);
        var tokens = login("regular@example.com", PASSWORD);

        mvc.perform(get("/admin/users").header(HttpHeaders.AUTHORIZATION, bearer(tokens)))
                .andExpect(status().isForbidden())
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.status").value(403));
    }

    @Test
    void adminCanListUsers() throws Exception {
        userService.create("root@example.com", PASSWORD, Role.ADMIN);
        var tokens = login("root@example.com", PASSWORD);

        mvc.perform(get("/admin/users").header(HttpHeaders.AUTHORIZATION, bearer(tokens)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].email").value(hasItem("root@example.com")));
    }

    @Test
    void reusingRefreshTokenRevokesTheWholeFamily() throws Exception {
        register("reuse@example.com", PASSWORD);
        var first = login("reuse@example.com", PASSWORD).get("refreshToken").asText();
        var second = parse(refresh(first).andExpect(status().isOk()))
                .get("refreshToken")
                .asText();

        refresh(first).andExpect(status().isUnauthorized());

        refresh(second).andExpect(status().isUnauthorized());
    }

    @Test
    void repeatedFailuresLockTheAccount() throws Exception {
        register("locked@example.com", PASSWORD);
        for (int i = 0; i < 5; i++) {
            attemptLogin("locked@example.com", "incorrect-horse-42").andExpect(status().isUnauthorized());
        }

        attemptLogin("locked@example.com", PASSWORD)
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists(HttpHeaders.RETRY_AFTER))
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON));
    }

    private ResultActions register(String email, String password) throws Exception {
        return mvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body(Map.of("email", email, "password", password))));
    }

    private ResultActions attemptLogin(String email, String password) throws Exception {
        return mvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body(Map.of("email", email, "password", password))));
    }

    private JsonNode login(String email, String password) throws Exception {
        return parse(attemptLogin(email, password).andExpect(status().isOk()));
    }

    private ResultActions refresh(String refreshToken) throws Exception {
        return mvc.perform(post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body(Map.of("refreshToken", refreshToken))));
    }

    private JsonNode parse(ResultActions result) throws Exception {
        return json.readTree(result.andReturn().getResponse().getContentAsString());
    }

    private String body(Map<String, String> fields) throws Exception {
        return json.writeValueAsString(fields);
    }

    private static String bearer(JsonNode tokens) {
        return "Bearer " + tokens.get("accessToken").asText();
    }
}
