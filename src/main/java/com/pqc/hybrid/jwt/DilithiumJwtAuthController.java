package com.pqc.hybrid.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Demo endpoints for Phase 4 — Dilithium-3 signed JWT authentication.
 *
 * ENDPOINTS:
 *
 *   POST /auth/token
 *     Issues a Dilithium-3 signed JWT token given username + password credentials.
 *     In this demo, any username is accepted with the configured demo password.
 *     In production, replace the credential check with your UserDetailsService.
 *
 *   GET /api/secure
 *     Protected endpoint — requires a valid Dilithium-3 JWT in the Authorization header.
 *     Returns a JSON response showing the authenticated principal and its roles.
 *
 * USAGE:
 *
 *   # 1. Get a token
 *   curl -X POST http://localhost:8080/auth/token \
 *        -H "Content-Type: application/json" \
 *        -d '{"username":"alice","password":"secret"}'
 *
 *   # 2. Use the token
 *   curl http://localhost:8080/api/secure \
 *        -H "Authorization: Bearer <token>"
 */
@RestController
public class DilithiumJwtAuthController {

    private static final Logger log = LoggerFactory.getLogger(DilithiumJwtAuthController.class);

    private final DilithiumJwtService jwtService;
    private final String              demoPassword;

    public DilithiumJwtAuthController(DilithiumJwtService jwtService,
                                      @Value("${pqc.jwt.demo-password:secret}") String demoPassword) {
        this.jwtService   = jwtService;
        this.demoPassword = demoPassword;
    }

    // ─────────────────────────────────────────────────────────────
    // POST /auth/token — issue a Dilithium-3 JWT
    // ─────────────────────────────────────────────────────────────

    @PostMapping("/auth/token")
    public ResponseEntity<Map<String, Object>> issueToken(@RequestBody TokenRequest request) {
        if (request.username() == null || request.username().isBlank()) {
            return badRequest("username is required");
        }
        if (!constantTimeEquals(demoPassword, request.password())) {
            log.debug("Login failed for username={}", request.username());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Invalid credentials"));
        }

        try {
            List<String> roles = List.of("USER");
            String token = jwtService.issueToken(request.username(), roles);

            Map<String, Object> body = new LinkedHashMap<>();
            body.put("token",            token);
            body.put("expiresInSeconds", jwtService.getTtlSeconds());
            body.put("algorithm",        DilithiumJwtService.ALG_HEADER);
            body.put("quantumSafe",      true);

            log.debug("Issued Dilithium-3 JWT for username={}", request.username());
            return ResponseEntity.ok(body);

        } catch (Exception e) {
            log.error("Token issuance failed for username={}", request.username(), e);
            return ResponseEntity.internalServerError()
                .body(Map.of("error", "Token issuance failed: " + e.getMessage()));
        }
    }

    // ─────────────────────────────────────────────────────────────
    // GET /api/secure — protected resource (requires valid JWT)
    // ─────────────────────────────────────────────────────────────

    @GetMapping("/api/secure")
    public ResponseEntity<Map<String, Object>> secureEndpoint(
            @AuthenticationPrincipal String subject) {

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("message",     "Hello " + subject + " — you are authenticated with a quantum-safe Dilithium-3 JWT");
        body.put("subject",     subject);
        body.put("algorithm",   DilithiumJwtService.ALG_HEADER);
        body.put("quantumSafe", true);
        return ResponseEntity.ok(body);
    }

    // ─────────────────────────────────────────────────────────────
    // Request record
    // ─────────────────────────────────────────────────────────────

    public record TokenRequest(String username, String password) {}

    // ─────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────

    private ResponseEntity<Map<String, Object>> badRequest(String message) {
        return ResponseEntity.badRequest().body(Map.of("error", message));
    }

    /**
     * Constant-time string comparison — avoids leaking password length/prefix
     * via response-time differences that {@link String#equals} would expose.
     */
    private static boolean constantTimeEquals(String expected, String actual) {
        if (actual == null) return false;
        return MessageDigest.isEqual(
            expected.getBytes(StandardCharsets.UTF_8),
            actual.getBytes(StandardCharsets.UTF_8));
    }
}
