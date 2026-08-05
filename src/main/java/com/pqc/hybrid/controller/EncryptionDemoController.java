package com.pqc.hybrid.controller;

import java.util.Map;
import java.util.Set;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.pqc.hybrid.crypto.AesGcmEngine;
import com.pqc.hybrid.crypto.PqcEncryptionService;
import com.pqc.hybrid.handshake.ClientCapability;
import com.pqc.hybrid.handshake.HandshakeSession;
import com.pqc.hybrid.handshake.HybridHandshakeOrchestrator;

/**
 * Phase 2 — End-to-End Encryption Demo Controller
 *
 * Shows the FULL pipeline: key exchange → AES-256-GCM encrypt → decrypt
 *
 * ─────────────────────────────────────────────────────────────────────
 * QUICK TEST COMMANDS:
 * ─────────────────────────────────────────────────────────────────────
 *
 * # 1. Full pipeline in one shot (hybrid session + encrypt + decrypt)
 *   curl -s -X POST "http://localhost:8080/api/encrypt/e2e?message=HelloQuantumWorld" \
 *        | python3 -m json.tool
 *
 * # 2. Step-by-step: establish a session
 *   curl -s -X POST "http://localhost:8080/api/encrypt/session?clientId=myapp" \
 *        | python3 -m json.tool
 *   # Note the sessionId from the response
 *
 * # 3. Step-by-step: encrypt using that session
 *   curl -s -X POST "http://localhost:8080/api/encrypt/encrypt" \
 *        -H "Content-Type: application/json" \
 *        -d '{"sessionId":"<YOUR_SESSION_ID>","plaintext":"My secret data"}' \
 *        | python3 -m json.tool
 *   # Note the ciphertext from the response
 *
 * # 4. Step-by-step: decrypt it back
 *   curl -s -X POST "http://localhost:8080/api/encrypt/decrypt" \
 *        -H "Content-Type: application/json" \
 *        -d '{"sessionId":"<YOUR_SESSION_ID>","ciphertext":"<CIPHERTEXT>"}' \
 *        | python3 -m json.tool
 *
 * # 5. Tamper test — proves GCM authentication works
 *   curl -s -X POST "http://localhost:8080/api/encrypt/tamper-test" \
 *        | python3 -m json.tool
 *
 * # 6. Compare all three modes (classical vs pqc vs hybrid encryption)
 *   curl -s "http://localhost:8080/api/encrypt/compare-modes" \
 *        | python3 -m json.tool
 */
@RestController
@RequestMapping("/api/encrypt")
public class EncryptionDemoController {

    private final PqcEncryptionService      pqcEncryption;
    private final HybridHandshakeOrchestrator orchestrator;
    private final AesGcmEngine              aesGcm;

    public EncryptionDemoController(PqcEncryptionService pqcEncryption,
                                     HybridHandshakeOrchestrator orchestrator,
                                     AesGcmEngine aesGcm) {
        this.pqcEncryption = pqcEncryption;
        this.orchestrator  = orchestrator;
        this.aesGcm        = aesGcm;
    }

    // ─────────────────────────────────────────────────────────────
    // FULL PIPELINE — one call does everything
    // ─────────────────────────────────────────────────────────────

    /**
     * Full end-to-end demo: handshake + encrypt + decrypt in one shot.
     * Best endpoint to start with — proves the whole chain works.
     */
    @PostMapping("/e2e")
    public ResponseEntity<Map<String, Object>> endToEnd(
            @RequestParam(defaultValue = "Hello, Quantum-Safe World!") String message)
            throws Exception {

        PqcEncryptionService.PipelineResult result =
            pqcEncryption.runEndToEndPipeline("demo-client", message);

        return ResponseEntity.ok(Map.of(
            "pipeline",            "Kyber-768 + ECDHE-P384  →  AES-256-GCM",
            "session",             result.session(),
            "original",            result.decryptedText(),
            "plaintextBytes",      result.plaintextBytes(),
            "ciphertextBytes",     result.ciphertextBytes(),
            "ciphertext",          result.ciphertextBase64(),
            "decryptedText",       result.decryptedText(),
            "roundTripVerified",   result.roundTripVerified(),
            "totalDurationMs",     result.totalDurationMs()
        ));
    }

    // ─────────────────────────────────────────────────────────────
    // STEP BY STEP — session, then encrypt, then decrypt
    // ─────────────────────────────────────────────────────────────

    /**
     * Step 1 — Establish a hybrid session. Returns sessionId for next steps.
     */
    @PostMapping("/session")
    public ResponseEntity<Map<String, Object>> createSession(
            @RequestParam(defaultValue = "my-client") String clientId)
            throws Exception {

        HandshakeSession session = pqcEncryption.establishHybridSession(clientId);

        return ResponseEntity.ok(Map.of(
            "sessionId",          session.getSessionId(),
            "cipherMode",         session.getCipherMode().name(),
            "quantumSafe",        session.isQuantumSafe(),
            "keyExchange",        session.getClassicalAlgorithm() + " + " + session.getPqcKemAlgorithm(),
            "dataEncryption",     "AES-256-GCM",
            "handshakeDurationMs", session.getHandshakeDurationMs(),
            "instructions",       "Use sessionId in /api/encrypt/encrypt and /api/encrypt/decrypt"
        ));
    }

    /**
     * Step 2 — Encrypt a payload using an established session.
     */
    @PostMapping("/encrypt")
    public ResponseEntity<Map<String, Object>> encrypt(
            @RequestBody EncryptRequest req) throws Exception {

        String ciphertext = pqcEncryption.encryptForSession(req.sessionId(), req.plaintext());

        // Show breakdown of the wire format
        byte[] wire = java.util.Base64.getDecoder().decode(ciphertext);

        return ResponseEntity.ok(Map.of(
            "sessionId",       req.sessionId(),
            "originalLength",  req.plaintext().length(),
            "ciphertext",      ciphertext,
            "wireBreakdown", Map.of(
                "ivBytes",          AesGcmEngine.IV_LENGTH_BYTES,
                "gcmTagBytes",      AesGcmEngine.TAG_LENGTH_BITS / 8,
                "ciphertextBytes",  wire.length - AesGcmEngine.IV_LENGTH_BYTES,
                "totalWireBytes",   wire.length
            ),
            "algorithm",       "AES-256-GCM",
            "note",            "IV is unique per encryption — safe to send with ciphertext"
        ));
    }

    /**
     * Step 3 — Decrypt back to plaintext.
     */
    @PostMapping("/decrypt")
    public ResponseEntity<Map<String, Object>> decrypt(
            @RequestBody DecryptRequest req) throws Exception {

        String plaintext = pqcEncryption.decryptForSession(req.sessionId(), req.ciphertext());

        return ResponseEntity.ok(Map.of(
            "sessionId",   req.sessionId(),
            "plaintext",   plaintext,
            "gcmVerified", true,   // if we got here, GCM tag verified — no tampering
            "note",        "GCM authentication tag verified — payload integrity confirmed"
        ));
    }

    // ─────────────────────────────────────────────────────────────
    // TAMPER TEST — proves GCM authentication works
    // ─────────────────────────────────────────────────────────────

    /**
     * Proves AES-GCM authentication works.
     * Encrypts data, flips a bit in the ciphertext, then tries to decrypt.
     * The GCM tag check must reject the tampered ciphertext.
     */
    @PostMapping("/tamper-test")
    public ResponseEntity<Map<String, Object>> tamperTest() throws Exception {
        String original = "This data must not be tampered with";

        // Encrypt with a hybrid session
        HandshakeSession session = pqcEncryption.establishHybridSession("tamper-test");
        String sessionId         = session.getSessionId();
        String ciphertext        = pqcEncryption.encryptForSession(sessionId, original);

        // Tamper: flip a byte in the middle of the ciphertext
        byte[] wire = java.util.Base64.getDecoder().decode(ciphertext);
        wire[wire.length / 2] ^= 0xFF;  // flip all bits in one byte
        String tamperedCiphertext = java.util.Base64.getEncoder().encodeToString(wire);

        // Try to decrypt the tampered ciphertext
        String tamperResult;
        boolean tamperDetected;
        try {
            pqcEncryption.decryptForSession(sessionId, tamperedCiphertext);
            tamperResult   = "FAIL — tampered ciphertext was accepted (should not happen)";
            tamperDetected = false;
        } catch (Exception e) {
            tamperResult   = "Tampering detected and rejected: " + e.getClass().getSimpleName();
            tamperDetected = true;
        }

        // Verify original still decrypts correctly
        String recovered       = pqcEncryption.decryptForSession(sessionId, ciphertext);
        boolean originalOk     = original.equals(recovered);

        return ResponseEntity.ok(Map.of(
            "originalData",        original,
            "tamperDetected",      tamperDetected,
            "tamperResult",        tamperResult,
            "originalStillDecrypts", originalOk,
            "conclusion",          tamperDetected
                ? "✓ AES-GCM authentication is working — any tampering is detected automatically"
                : "✗ Something is wrong — tampered data should have been rejected"
        ));
    }

    // ─────────────────────────────────────────────────────────────
    // MODE COMPARISON — classical vs pqc vs hybrid
    // ─────────────────────────────────────────────────────────────

    /**
     * Encrypt the same payload in all three modes side by side.
     * Shows that the ciphertext size is the same — mode only affects
     * how the AES key was derived, not the data encryption itself.
     */
    @GetMapping("/compare-modes")
    public ResponseEntity<Map<String, Object>> compareModes() throws Exception {
        String payload = "{\"orderId\":\"ORD-12345\",\"amount\":9999.99,\"currency\":\"USD\"}";

        // Classical session
        HandshakeSession classical = orchestrator.orchestrate(
            ClientCapability.builder().pqcCapable(false).clientId("compare").build());
        String classicalCt = pqcEncryption.encryptForSession(classical.getSessionId(), payload);

        // PQC-Only session
        HandshakeSession pqcOnly = orchestrator.orchestrate(
            ClientCapability.builder().pqcCapable(true).hybridCapable(false)
                .supportedAlgorithms(Set.of("Kyber-768")).clientId("compare").build());
        String pqcOnlyCt = pqcEncryption.encryptForSession(pqcOnly.getSessionId(), payload);

        // Hybrid session
        HandshakeSession hybrid = orchestrator.orchestrate(
            ClientCapability.builder().pqcCapable(true).hybridCapable(true)
                .supportedAlgorithms(Set.of("Kyber-768")).clientId("compare").build());
        String hybridCt = pqcEncryption.encryptForSession(hybrid.getSessionId(), payload);

        // All should decrypt back to the same original payload
        String classicalDecrypted = pqcEncryption.decryptForSession(classical.getSessionId(), classicalCt);
        String pqcOnlyDecrypted   = pqcEncryption.decryptForSession(pqcOnly.getSessionId(), pqcOnlyCt);
        String hybridDecrypted    = pqcEncryption.decryptForSession(hybrid.getSessionId(), hybridCt);

        return ResponseEntity.ok(Map.of(
            "payload",          payload,
            "payloadBytes",     payload.length(),
            "dataEncryption",   "AES-256-GCM (same for all modes — only key derivation differs)",
            "modes", Map.of(
                "CLASSICAL", Map.of(
                    "keyDerivation",    "ECDHE-P384 only",
                    "quantumSafe",      false,
                    "ciphertextBytes",  java.util.Base64.getDecoder().decode(classicalCt).length,
                    "decryptVerified",  payload.equals(classicalDecrypted)
                ),
                "PQC_ONLY", Map.of(
                    "keyDerivation",    "Kyber-768 only",
                    "quantumSafe",      true,
                    "ciphertextBytes",  java.util.Base64.getDecoder().decode(pqcOnlyCt).length,
                    "decryptVerified",  payload.equals(pqcOnlyDecrypted)
                ),
                "HYBRID", Map.of(
                    "keyDerivation",    "Kyber-768 + ECDHE-P384 combined",
                    "quantumSafe",      true,
                    "ciphertextBytes",  java.util.Base64.getDecoder().decode(hybridCt).length,
                    "decryptVerified",  payload.equals(hybridDecrypted)
                )
            ),
            "insight", "Ciphertext size is identical across modes — the difference is " +
                       "HOW the AES key was derived, not how the data is encrypted"
        ));
    }

    // ─────────────────────────────────────────────────────────────
    // REQUEST / RESPONSE RECORDS
    // ─────────────────────────────────────────────────────────────

    public record EncryptRequest(String sessionId, String plaintext) {}
    public record DecryptRequest(String sessionId, String ciphertext) {}
}
