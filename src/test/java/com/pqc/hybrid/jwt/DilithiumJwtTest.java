package com.pqc.hybrid.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.*;

import java.security.Security;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for Phase 4 — Dilithium-3 signed JWT tokens.
 *
 * All tests use ephemeral keys (Optional.empty()) — no KMS or external
 * dependencies required. The same logic applies when Phase 3 keys are in use.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class DilithiumJwtTest {

    private static DilithiumJwtService  jwtService;
    private static DilithiumKeyPairHolder keyHolder;

    @BeforeAll
    static void setup() throws Exception {
        if (Security.getProvider("BC")    == null) Security.insertProviderAt(new BouncyCastleProvider(),    1);
        if (Security.getProvider("BCPQC") == null) Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);

        // Use ephemeral keys — no Phase 3 required for these tests
        keyHolder  = new DilithiumKeyPairHolder(Optional.empty());
        jwtService = new DilithiumJwtService(keyHolder, new ObjectMapper(), 60);
    }

    // ── Issuance and validation ───────────────────────────────────

    @Test @Order(1)
    @DisplayName("Issue + validate round-trip preserves subject and roles")
    void issueAndValidateRoundTrip() throws Exception {
        String token = jwtService.issueToken("alice", List.of("USER", "ADMIN"));
        DilithiumJwt jwt = jwtService.validateToken(token);

        assertThat(jwt.subject()).isEqualTo("alice");
        assertThat(jwt.roles()).containsExactly("USER", "ADMIN");
        assertThat(jwt.algorithm()).isEqualTo("DILITHIUM3");
        assertThat(jwt.isExpired()).isFalse();

        System.out.printf("✓ Round-trip: sub=%s roles=%s sigSize≈3293B%n",
            jwt.subject(), jwt.roles());
    }

    @Test @Order(2)
    @DisplayName("Token has exactly three Base64URL segments")
    void tokenHasThreeSegments() throws Exception {
        String token = jwtService.issueToken("bob", List.of("USER"));
        String[] parts = token.split("\\.");
        assertThat(parts).hasSize(3);
        // Each segment must be non-empty Base64URL
        for (String part : parts) {
            assertThat(part).isNotBlank();
        }
        System.out.println("✓ Token structure: header.payload.signature (3 segments)");
    }

    @Test @Order(3)
    @DisplayName("Header contains alg=DILITHIUM3 and typ=JWT")
    void headerContainsCorrectAlgorithm() throws Exception {
        String token = jwtService.issueToken("carol", List.of("USER"));
        String headerJson = new String(Base64.getUrlDecoder().decode(token.split("\\.")[0]));
        assertThat(headerJson).contains("\"alg\":\"DILITHIUM3\"");
        assertThat(headerJson).contains("\"typ\":\"JWT\"");
        System.out.println("✓ Header: " + headerJson);
    }

    @Test @Order(4)
    @DisplayName("Roles round-trip: multi-role list serialised and deserialised correctly")
    void rolesRoundTrip() throws Exception {
        List<String> roles = List.of("USER", "ADMIN", "OPERATOR");
        String token = jwtService.issueToken("dave", roles);
        DilithiumJwt jwt = jwtService.validateToken(token);

        assertThat(jwt.roles()).hasSize(3);
        assertThat(jwt.roles()).containsExactlyInAnyOrder("USER", "ADMIN", "OPERATOR");
        System.out.println("✓ Roles round-trip: " + jwt.roles());
    }

    // ── Security: rejection cases ─────────────────────────────────

    @Test @Order(5)
    @DisplayName("Tampered payload rejected — Dilithium-3 signature fails")
    void tamperedPayloadRejected() throws Exception {
        String token = jwtService.issueToken("eve", List.of("USER"));
        String[] parts = token.split("\\.");

        // Encode a modified payload with a different subject
        String maliciousPayload = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"sub\":\"admin\",\"iat\":9999999999,\"exp\":9999999999,\"roles\":[\"ADMIN\"]}".getBytes());

        String tampered = parts[0] + "." + maliciousPayload + "." + parts[2];

        assertThatThrownBy(() -> jwtService.validateToken(tampered))
            .isInstanceOf(DilithiumJwtException.class)
            .satisfies(e -> assertThat(((DilithiumJwtException) e).getReason())
                .isEqualTo(DilithiumJwtException.Reason.INVALID_SIGNATURE));
        System.out.println("✓ Tampered payload correctly rejected by Dilithium-3 verification");
    }

    @Test @Order(6)
    @DisplayName("Tampered signature bytes rejected")
    void tamperedSignatureRejected() throws Exception {
        String token = jwtService.issueToken("frank", List.of("USER"));
        String[] parts = token.split("\\.");

        byte[] sigBytes = Base64.getUrlDecoder().decode(parts[2]);
        sigBytes[sigBytes.length / 2] ^= 0xFF; // flip bits
        String corruptedSig = Base64.getUrlEncoder().withoutPadding().encodeToString(sigBytes);

        String tampered = parts[0] + "." + parts[1] + "." + corruptedSig;

        assertThatThrownBy(() -> jwtService.validateToken(tampered))
            .isInstanceOf(DilithiumJwtException.class)
            .satisfies(e -> assertThat(((DilithiumJwtException) e).getReason())
                .isEqualTo(DilithiumJwtException.Reason.INVALID_SIGNATURE));
        System.out.println("✓ Corrupted signature bytes correctly rejected");
    }

    @Test @Order(7)
    @DisplayName("Token signed with a different keypair is rejected")
    void wrongPublicKeyRejected() throws Exception {
        // Issue with key A
        String token = jwtService.issueToken("grace", List.of("USER"));

        // Validate with a completely different service (different ephemeral keypair)
        DilithiumKeyPairHolder otherHolder = new DilithiumKeyPairHolder(Optional.empty());
        DilithiumJwtService otherService = new DilithiumJwtService(otherHolder, new ObjectMapper(), 60);

        assertThatThrownBy(() -> otherService.validateToken(token))
            .isInstanceOf(DilithiumJwtException.class)
            .satisfies(e -> assertThat(((DilithiumJwtException) e).getReason())
                .isEqualTo(DilithiumJwtException.Reason.INVALID_SIGNATURE));
        System.out.println("✓ Token from different keypair correctly rejected");
    }

    @Test @Order(8)
    @DisplayName("Expired token rejected with EXPIRED reason")
    void expiredTokenRejected() throws Exception {
        // Create a service with TTL of 0 minutes — token expires immediately
        DilithiumJwtService shortLivedService = new DilithiumJwtService(keyHolder, new ObjectMapper(), 0);
        String token = shortLivedService.issueToken("henry", List.of("USER"));

        // Brief pause to ensure exp is in the past
        Thread.sleep(1100);

        assertThatThrownBy(() -> shortLivedService.validateToken(token))
            .isInstanceOf(DilithiumJwtException.class)
            .satisfies(e -> assertThat(((DilithiumJwtException) e).getReason())
                .isEqualTo(DilithiumJwtException.Reason.EXPIRED));
        System.out.println("✓ Expired token correctly rejected");
    }

    @Test @Order(9)
    @DisplayName("Malformed token (not three segments) rejected with MALFORMED reason")
    void malformedTokenRejected() throws Exception {
        assertThatThrownBy(() -> jwtService.validateToken("not-a-jwt"))
            .isInstanceOf(DilithiumJwtException.class)
            .satisfies(e -> assertThat(((DilithiumJwtException) e).getReason())
                .isEqualTo(DilithiumJwtException.Reason.MALFORMED));
        System.out.println("✓ Non-JWT string rejected as MALFORMED");
    }

    @Test @Order(10)
    @DisplayName("Two-segment token rejected with MALFORMED reason")
    void missingSegmentsRejected() throws Exception {
        assertThatThrownBy(() -> jwtService.validateToken("header.payload"))
            .isInstanceOf(DilithiumJwtException.class)
            .satisfies(e -> assertThat(((DilithiumJwtException) e).getReason())
                .isEqualTo(DilithiumJwtException.Reason.MALFORMED));
        System.out.println("✓ Two-segment string rejected as MALFORMED");
    }

    @Test @Order(11)
    @DisplayName("DilithiumKeyPairHolder: ephemeral mode source is 'ephemeral'")
    void keyHolderEphemeralSource() {
        assertThat(keyHolder.getSource()).isEqualTo("ephemeral");
        assertThat(keyHolder.getPublicKey()).isNotNull();
        assertThat(keyHolder.getPrivateKey()).isNotNull();
        System.out.println("✓ KeyHolder source: " + keyHolder.getSource());
    }
}
