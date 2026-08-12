package com.pqc.hybrid.crypto;

import com.pqc.hybrid.handshake.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.*;

import javax.crypto.AEADBadTagException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for AES-256-GCM engine and full end-to-end encryption pipeline.
 *
 * Tests cover:
 *   - Encrypt/decrypt round-trip
 *   - Tamper detection (GCM authentication)
 *   - IV uniqueness (never reused)
 *   - Wrong session ID rejected (AAD mismatch)
 *   - Wrong key rejected
 *   - Wire format serialization
 *   - Full pipeline: Kyber handshake → AES-256-GCM encrypt → decrypt
 *   - All three cipher modes (CLASSICAL, PQC_ONLY, HYBRID)
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AesGcmEngineTest {

    private static AesGcmEngine                aesGcm;
    private static HybridHandshakeOrchestrator orchestrator;
    private static PqcEncryptionService        pqcEncryption;

    @BeforeAll
    static void setup() throws Exception {
        if (Security.getProvider("BC")    == null) Security.insertProviderAt(new BouncyCastleProvider(),    1);
        if (Security.getProvider("BCPQC") == null) Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);
        aesGcm        = new AesGcmEngine();
        orchestrator  = new HybridHandshakeOrchestrator();
        pqcEncryption = new PqcEncryptionService(orchestrator, aesGcm, new KyberKemEngine());
    }

    // ── AES-GCM Core Tests ────────────────────────────────────────

    @Test @Order(1)
    @DisplayName("AES-256-GCM: basic encrypt/decrypt round-trip")
    void basicRoundTrip() throws Exception {
        byte[] key      = randomKey();
        String session  = "test-session-001";
        String original = "Hello, Quantum-Safe World!";

        AesGcmEngine.EncryptedPayload payload = aesGcm.encryptString(key, original, session);
        String decrypted = aesGcm.decryptString(key, payload);

        assertThat(decrypted).isEqualTo(original);
        assertThat(payload.iv()).hasSize(AesGcmEngine.IV_LENGTH_BYTES);
        assertThat(payload.ciphertextWithTag().length)
            .isGreaterThan(original.length()); // data + 16-byte GCM tag

        System.out.printf("✓ Encrypt: %d bytes → %d wire bytes (IV=%dB + data + 16B tag)%n",
            original.length(), payload.totalBytes(), AesGcmEngine.IV_LENGTH_BYTES);
    }

    @Test @Order(2)
    @DisplayName("AES-256-GCM: tampered ciphertext is rejected (GCM tag check)")
    void tamperDetection() throws Exception {
        byte[] key     = randomKey();
        String session = "tamper-test-session";
        AesGcmEngine.EncryptedPayload payload =
            aesGcm.encryptString(key, "Sensitive financial data: $9,999.99", session);

        // Flip a byte in the ciphertext
        byte[] tampered = Arrays.copyOf(payload.ciphertextWithTag(), payload.ciphertextWithTag().length);
        tampered[tampered.length / 2] ^= 0xFF;
        AesGcmEngine.EncryptedPayload tamperedPayload =
            new AesGcmEngine.EncryptedPayload(payload.iv(), tampered, session);

        assertThatThrownBy(() -> aesGcm.decryptString(key, tamperedPayload))
            .isInstanceOf(AEADBadTagException.class);

        System.out.println("✓ Tampered ciphertext correctly rejected by GCM authentication tag");
    }

    @Test @Order(3)
    @DisplayName("AES-256-GCM: wrong session ID rejected (AAD mismatch)")
    void wrongSessionIdRejected() throws Exception {
        byte[] key = randomKey();
        AesGcmEngine.EncryptedPayload payload =
            aesGcm.encryptString(key, "Secret payload", "session-A");

        // Try to decrypt with a different session ID
        AesGcmEngine.EncryptedPayload wrongSession =
            new AesGcmEngine.EncryptedPayload(payload.iv(), payload.ciphertextWithTag(), "session-B");

        assertThatThrownBy(() -> aesGcm.decryptString(key, wrongSession))
            .isInstanceOf(AEADBadTagException.class);

        System.out.println("✓ Wrong session ID rejected — ciphertext is bound to its session via AAD");
    }

    @Test @Order(4)
    @DisplayName("AES-256-GCM: wrong key cannot decrypt")
    void wrongKeyRejected() throws Exception {
        byte[] correctKey = randomKey();
        byte[] wrongKey   = randomKey();
        String session    = "test-session";

        AesGcmEngine.EncryptedPayload payload =
            aesGcm.encryptString(correctKey, "Cannot decrypt without correct key", session);

        assertThatThrownBy(() -> aesGcm.decryptString(wrongKey, payload))
            .isInstanceOf(AEADBadTagException.class);

        System.out.println("✓ Wrong key rejected by GCM authentication");
    }

    @Test @Order(5)
    @DisplayName("AES-256-GCM: every encryption uses a unique IV")
    void ivIsUniquePerEncryption() throws Exception {
        byte[] key     = randomKey();
        String session = "iv-test-session";
        int    runs    = 100;

        Set<String> ivs = new HashSet<>();
        for (int i = 0; i < runs; i++) {
            AesGcmEngine.EncryptedPayload p = aesGcm.encryptString(key, "same plaintext", session);
            ivs.add(Arrays.toString(p.iv()));
        }

        assertThat(ivs).hasSize(runs); // all IVs must be unique
        System.out.printf("✓ %d encryptions produced %d unique IVs (no reuse)%n", runs, ivs.size());
    }

    @Test @Order(6)
    @DisplayName("AES-256-GCM: ciphertexts are non-deterministic (same input → different output)")
    void ciphertextsAreNonDeterministic() throws Exception {
        byte[] key     = randomKey();
        String session = "nd-session";
        String message = "same message every time";

        AesGcmEngine.EncryptedPayload p1 = aesGcm.encryptString(key, message, session);
        AesGcmEngine.EncryptedPayload p2 = aesGcm.encryptString(key, message, session);

        // Different IVs → different ciphertexts (even for identical plaintext)
        assertThat(p1.ciphertextWithTag()).isNotEqualTo(p2.ciphertextWithTag());
        // But both decrypt correctly
        assertThat(aesGcm.decryptString(key, p1)).isEqualTo(message);
        assertThat(aesGcm.decryptString(key, p2)).isEqualTo(message);

        System.out.println("✓ Non-deterministic: same plaintext produces different ciphertexts ✓");
    }

    @Test @Order(7)
    @DisplayName("AES-256-GCM: invalid key size rejected")
    void invalidKeySizeRejected() {
        byte[] shortKey = new byte[16]; // 128-bit, not 256-bit
        assertThatThrownBy(() -> aesGcm.encryptString(shortKey, "test", "session"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("32-byte");

        System.out.println("✓ Non-256-bit key correctly rejected");
    }

    @Test @Order(8)
    @DisplayName("AES-256-GCM: wire format serialization round-trip")
    void wireFormatRoundTrip() throws Exception {
        byte[] key     = randomKey();
        String session = "wire-test";
        String message = "Wire format test payload";

        AesGcmEngine.EncryptedPayload original = aesGcm.encryptString(key, message, session);
        String base64  = aesGcm.toBase64Wire(original);
        AesGcmEngine.EncryptedPayload restored = aesGcm.fromBase64Wire(base64, session);
        String decrypted = aesGcm.decryptString(key, restored);

        assertThat(decrypted).isEqualTo(message);
        assertThat(base64).doesNotContain(" "); // safe for JSON/HTTP headers

        System.out.printf("✓ Wire format: %d chars → Base64(%d chars) → decrypted ✓%n",
            message.length(), base64.length());
    }

    // ── Full Pipeline Tests (Kyber handshake → AES-256-GCM) ──────

    @Test @Order(9)
    @DisplayName("E2E: HYBRID handshake → AES-256-GCM encrypt/decrypt")
    void hybridHandshakeToAesGcm() throws Exception {
        HandshakeSession session = pqcEncryption.establishHybridSession("e2e-test");
        String payload   = "{\"userId\":\"usr-001\",\"role\":\"admin\",\"data\":\"sensitive\"}";

        String ciphertext = pqcEncryption.encryptForSession(session.getSessionId(), payload);
        String decrypted  = pqcEncryption.decryptForSession(session.getSessionId(), ciphertext);

        assertThat(decrypted).isEqualTo(payload);
        assertThat(session.getCipherMode()).isEqualTo(CipherMode.HYBRID);
        assertThat(session.isQuantumSafe()).isTrue();

        System.out.printf("✓ HYBRID E2E: Kyber-768 + ECDHE-P384 → AES-256-GCM%n");
        System.out.printf("  Payload: %d bytes → %d wire bytes%n",
            payload.length(), java.util.Base64.getDecoder().decode(ciphertext).length);
    }

    @Test @Order(10)
    @DisplayName("E2E: all three cipher modes encrypt/decrypt correctly")
    void allModesEncryptCorrectly() throws Exception {
        String payload = "This payload must survive all three cipher modes";

        for (CipherMode mode : CipherMode.values()) {
            ClientCapability cap = capFor(mode);
            HandshakeSession session = orchestrator.orchestrate(cap);

            String encrypted = pqcEncryption.encryptForSession(session.getSessionId(), payload);
            String decrypted = pqcEncryption.decryptForSession(session.getSessionId(), encrypted);

            assertThat(decrypted).isEqualTo(payload);
            assertThat(session.getCipherMode()).isEqualTo(mode);

            System.out.printf("✓ %s: encrypt/decrypt verified (quantum-safe: %s)%n",
                mode, session.isQuantumSafe());
        }
    }

    @Test @Order(11)
    @DisplayName("E2E: sessions cannot decrypt each other's ciphertext")
    void sessionIsolation() throws Exception {
        HandshakeSession session1 = pqcEncryption.establishHybridSession("client-1");
        HandshakeSession session2 = pqcEncryption.establishHybridSession("client-2");

        String encrypted1 = pqcEncryption.encryptForSession(session1.getSessionId(), "client-1 secret");

        // Session 2 must NOT be able to decrypt session 1's ciphertext
        assertThatThrownBy(() ->
            pqcEncryption.decryptForSession(session2.getSessionId(), encrypted1))
            .isInstanceOf(Exception.class);

        System.out.println("✓ Sessions are fully isolated — cross-session decryption rejected");
    }

    @Test @Order(12)
    @DisplayName("E2E: PipelineResult contains all expected fields")
    void pipelineResultComplete() throws Exception {
        PqcEncryptionService.PipelineResult result =
            pqcEncryption.runEndToEndPipeline("pipeline-test", "Test payload for pipeline");

        assertThat(result.roundTripVerified()).isTrue();
        assertThat(result.session().cipherMode()).isEqualTo("HYBRID");
        assertThat(result.session().quantumSafe()).isTrue();
        assertThat(result.ciphertextBytes()).isGreaterThan(result.plaintextBytes());
        assertThat(result.totalDurationMs()).isGreaterThan(0);
        assertThat(result.decryptedText()).isEqualTo("Test payload for pipeline");

        System.out.printf("✓ Pipeline: %d bytes → %d wire bytes in %.2f ms%n",
            result.plaintextBytes(), result.ciphertextBytes(), result.totalDurationMs());
    }

    @Test @Order(13)
    @DisplayName("Performance: 50 encrypt+decrypt operations (HYBRID mode)")
    void performance() throws Exception {
        HandshakeSession session = pqcEncryption.establishHybridSession("perf-test");
        String payload = "{\"transactionId\":\"TXN-999\",\"amount\":1234.56,\"currency\":\"USD\"}";
        int runs = 50;
        long total = 0;

        for (int i = 0; i < runs; i++) {
            long t = System.nanoTime();
            String ct = pqcEncryption.encryptForSession(session.getSessionId(), payload);
            pqcEncryption.decryptForSession(session.getSessionId(), ct);
            total += System.nanoTime() - t;
        }

        double avgMs = total / runs / 1_000_000.0;
        System.out.printf("✓ AES-256-GCM encrypt+decrypt avg: %.4f ms (%d runs)%n", avgMs, runs);
        assertThat(avgMs).isLessThan(50); // well under 50ms
    }

    // ── EncryptedPayload equals()/hashCode() — record with byte[] fields ────

    @Test @Order(14)
    @DisplayName("EncryptedPayload: two instances with identical content are equal (content, not reference)")
    void encryptedPayloadContentEquality() {
        byte[] iv1 = {1, 2, 3};
        byte[] iv2 = {1, 2, 3}; // same content, different array instance
        byte[] ct1 = {4, 5, 6};
        byte[] ct2 = {4, 5, 6};

        AesGcmEngine.EncryptedPayload a = new AesGcmEngine.EncryptedPayload(iv1, ct1, "session-1");
        AesGcmEngine.EncryptedPayload b = new AesGcmEngine.EncryptedPayload(iv2, ct2, "session-1");

        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
        System.out.println("✓ EncryptedPayload: content-based equals/hashCode, not reference-based");
    }

    @Test @Order(15)
    @DisplayName("EncryptedPayload: differing ciphertext content makes instances unequal")
    void encryptedPayloadContentInequality() {
        AesGcmEngine.EncryptedPayload a =
            new AesGcmEngine.EncryptedPayload(new byte[]{1, 2, 3}, new byte[]{4, 5, 6}, "s");
        AesGcmEngine.EncryptedPayload b =
            new AesGcmEngine.EncryptedPayload(new byte[]{1, 2, 3}, new byte[]{9, 9, 9}, "s");

        assertThat(a).isNotEqualTo(b);
        System.out.println("✓ EncryptedPayload: different ciphertext content -> not equal");
    }

    // ── Helpers ────────────────────────────────────────────────────

    private byte[] randomKey() {
        byte[] key = new byte[AesGcmEngine.KEY_LENGTH_BYTES];
        new SecureRandom().nextBytes(key);
        return key;
    }

    private ClientCapability capFor(CipherMode mode) {
        return switch (mode) {
            case HYBRID    -> ClientCapability.builder().pqcCapable(true).hybridCapable(true)
                               .supportedAlgorithms(Set.of("Kyber-768")).clientId("test").build();
            case PQC_ONLY  -> ClientCapability.builder().pqcCapable(true).hybridCapable(false)
                               .supportedAlgorithms(Set.of("Kyber-768")).clientId("test").build();
            case CLASSICAL -> ClientCapability.builder().pqcCapable(false).clientId("test").build();
        };
    }
}
