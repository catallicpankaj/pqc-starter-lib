package com.pqc.hybrid.jwt;

import tools.jackson.databind.ObjectMapper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.*;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.method.annotation.AuthenticationPrincipalArgumentResolver;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.security.Security;
import java.util.Optional;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Tests for {@link DilithiumJwtAuthController} at the HTTP layer — request validation,
 * the constant-time password check (fixed for a timing-safety bug; a regression test
 * here would have caught a revert), and the demo-controller's own response shapes.
 * Uses MockMvcBuilders.standaloneSetup() with the AuthenticationPrincipal resolver
 * registered manually, since standalone setup doesn't auto-configure Spring Security.
 */
class DilithiumJwtAuthControllerTest {

    private static MockMvc mockMvc;

    @BeforeAll
    static void setup() throws Exception {
        if (Security.getProvider("BC")    == null) Security.insertProviderAt(new BouncyCastleProvider(),    1);
        if (Security.getProvider("BCPQC") == null) Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);

        DilithiumKeyPairHolder holder = new DilithiumKeyPairHolder(Optional.empty());
        DilithiumJwtService jwtService = new DilithiumJwtService(holder, new ObjectMapper(), 60);
        DilithiumJwtAuthController controller = new DilithiumJwtAuthController(jwtService, "secret");

        mockMvc = MockMvcBuilders.standaloneSetup(controller)
            .setCustomArgumentResolvers(new AuthenticationPrincipalArgumentResolver())
            .build();
    }

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("POST /auth/token with the correct password -> 200 + a real Dilithium-3 token")
    void issueTokenWithCorrectPassword() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.post("/auth/token")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"alice\",\"password\":\"secret\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").isNotEmpty())
            .andExpect(jsonPath("$.algorithm").value("DILITHIUM3"))
            .andExpect(jsonPath("$.quantumSafe").value(true));
    }

    @Test
    @DisplayName("POST /auth/token with the wrong password -> 401, regression guard for the constant-time fix")
    void issueTokenWithWrongPasswordReturns401() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.post("/auth/token")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"alice\",\"password\":\"wrong-password\"}"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.error").value("Invalid credentials"));
    }

    @Test
    @DisplayName("POST /auth/token with a null password -> 401, not a 500 (MessageDigest.isEqual null-safety)")
    void issueTokenWithNullPasswordReturns401NotError() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.post("/auth/token")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"alice\"}")) // password field omitted -> null
            .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("POST /auth/token with a missing username -> 400")
    void issueTokenWithMissingUsernameReturns400() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.post("/auth/token")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"password\":\"secret\"}"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("username is required"));
    }

    @Test
    @DisplayName("POST /auth/token with a blank username -> 400")
    void issueTokenWithBlankUsernameReturns400() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.post("/auth/token")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"   \",\"password\":\"secret\"}"))
            .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("GET /api/secure with an authenticated principal -> 200, greets the subject")
    void secureEndpointWithAuthenticatedPrincipal() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
            new UsernamePasswordAuthenticationToken("alice", null, java.util.List.of()));

        mockMvc.perform(MockMvcRequestBuilders.get("/api/secure"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.subject").value("alice"))
            .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("alice")))
            .andExpect(jsonPath("$.quantumSafe").value(true));
    }
}
