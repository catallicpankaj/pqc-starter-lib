package com.pqc.hybrid.crypto;

import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.pqc.hybrid.handshake.ClientCapability;
import com.pqc.hybrid.handshake.HandshakeSession;
import com.pqc.hybrid.handshake.HybridHandshakeOrchestrator;

/**
 * ═══════════════════════════════════════════════════════════════════════
 * PQC ENCRYPTION SERVICE — End-to-End
 * The top-level service your application code talks to.
 * ═══════════════════════════════════════════════════════════════════════
 *
 * Combines Phase 1 (key exchange) + Phase 2 (data encryption) into
 * a single, simple API:
 *
 *   encrypt(sessionId, plaintext)  →  Base64 ciphertext
 *   decrypt(sessionId, ciphertext) →  plaintext
 *
 * FULL FLOW:
 *
 *   Client                              Server
 *   ──────                              ──────
 *   1. Handshake (Kyber + ECDHE)   →   Derive shared session key
 *   2. sessionKey = KDF(secrets)   =   sessionKey (same on both sides)
 *   3. AES-256-GCM encrypt(data)   →   AES-256-GCM decrypt(data)
 *
 * WHAT PROTECTS YOUR DATA:
 *
 *   Key Exchange:   Kyber-768 (quantum-safe) + ECDHE-P384 (classical)
 *   Data Encrypt:   AES-256-GCM (authenticated encryption)
 *   Integrity:      GCM tag — any tampering detected automatically
 *   Replay attack:  Session ID as AAD — ciphertext bound to one session
 *
 * USAGE:
 *
 *   // In your controller/service — just autowire and use:
 *   @Autowired PqcEncryptionService pqcEncryption;
 *
 *   // Establish a quantum-safe session
 *   HandshakeSession session = pqcEncryption.establishSession(clientCapability);
 *
 *   // Encrypt any payload
 *   String encrypted = pqcEncryption.encryptForSession(session.getSessionId(), myJsonPayload);
 *
 *   // Decrypt on the other side
 *   String decrypted = pqcEncryption.decryptForSession(session.getSessionId(), encrypted);
 */
@Service
public class PqcEncryptionService {

    private static final Logger log = LoggerFactory.getLogger(PqcEncryptionService.class);

    private final HybridHandshakeOrchestrator orchestrator;
    private final AesGcmEngine                aesGcm;

    public PqcEncryptionService(HybridHandshakeOrchestrator orchestrator, AesGcmEngine aesGcm) {
        this.orchestrator = orchestrator;
        this.aesGcm       = aesGcm;
    }

    // ─────────────────────────────────────────────────────────────
    // SESSION MANAGEMENT
    // ─────────────────────────────────────────────────────────────

    /**
     * Establish a quantum-safe encrypted session.
     * Mode is auto-selected based on client capability (HYBRID if supported).
     */
    public HandshakeSession establishSession(ClientCapability capability) throws Exception {
        return orchestrator.orchestrate(capability);
    }

    /**
     * Convenience: establish a HYBRID session (maximum security).
     */
    public HandshakeSession establishHybridSession(String clientId) throws Exception {
        ClientCapability cap = ClientCapability.builder()
            .pqcCapable(true)
            .hybridCapable(true)
            .supportedAlgorithms(Set.of("Kyber-768", "Dilithium-3"))
            .clientId(clientId)
            .build();
        return orchestrator.orchestrate(cap);
    }

    /**
     * Convenience: establish a CLASSICAL session (legacy client).
     */
    public HandshakeSession establishClassicalSession(String clientId) throws Exception {
        ClientCapability cap = ClientCapability.builder()
            .pqcCapable(false)
            .clientId(clientId)
            .build();
        return orchestrator.orchestrate(cap);
    }

    // ─────────────────────────────────────────────────────────────
    // ENCRYPT
    // ─────────────────────────────────────────────────────────────

    /**
     * Encrypt a string payload for a session.
     * Returns a Base64-encoded string safe for JSON / HTTP headers.
     *
     * @param sessionId  Session established via establishSession()
     * @param plaintext  Any string — JSON, plain text, etc.
     * @return           Base64-encoded ciphertext (IV + encrypted data + GCM tag)
     */
    public String encryptForSession(String sessionId, String plaintext) throws Exception {
        HandshakeSession session = getSessionOrThrow(sessionId);
        AesGcmEngine.EncryptedPayload payload = aesGcm.encryptString(
            session.getSessionKeyMaterial(), plaintext, sessionId);

        log.debug("[{}] Encrypted {} bytes → {} wire bytes ({})",
            sessionId, plaintext.length(), payload.totalBytes(),
            session.getCipherMode());

        return aesGcm.toBase64Wire(payload);
    }

    /**
     * Encrypt raw bytes for a session.
     */
    public String encryptBytesForSession(String sessionId, byte[] data) throws Exception {
        HandshakeSession session = getSessionOrThrow(sessionId);
        AesGcmEngine.EncryptedPayload payload = aesGcm.encrypt(
            session.getSessionKeyMaterial(), data, sessionId);
        return aesGcm.toBase64Wire(payload);
    }

    // ─────────────────────────────────────────────────────────────
    // DECRYPT
    // ─────────────────────────────────────────────────────────────

    /**
     * Decrypt a Base64-encoded ciphertext back to a string.
     * Automatically verifies GCM authentication tag — throws if tampered.
     *
     * @param sessionId  Same session ID used during encryption
     * @param base64     The Base64 string returned by encryptForSession()
     * @return           Original plaintext string
     */
    public String decryptForSession(String sessionId, String base64) throws Exception {
        HandshakeSession session = getSessionOrThrow(sessionId);
        AesGcmEngine.EncryptedPayload payload = aesGcm.fromBase64Wire(base64, sessionId);
        String plaintext = aesGcm.decryptString(session.getSessionKeyMaterial(), payload);

        log.debug("[{}] Decrypted {} wire bytes → {} chars",
            sessionId, payload.totalBytes(), plaintext.length());

        return plaintext;
    }

    /**
     * Decrypt back to raw bytes.
     */
    public byte[] decryptBytesForSession(String sessionId, String base64) throws Exception {
        HandshakeSession session = getSessionOrThrow(sessionId);
        AesGcmEngine.EncryptedPayload payload = aesGcm.fromBase64Wire(base64, sessionId);
        return aesGcm.decrypt(session.getSessionKeyMaterial(), payload);
    }

    // ─────────────────────────────────────────────────────────────
    // FULL PIPELINE — Encrypt + Decrypt in one call (for testing)
    // ─────────────────────────────────────────────────────────────

    /**
     * Full end-to-end pipeline result — useful for testing and demos.
     * Establishes a HYBRID session, encrypts, then decrypts and verifies.
     */
    public PipelineResult runEndToEndPipeline(String clientId, String plaintext) throws Exception {
        long start = System.nanoTime();

        // Step 1: Hybrid handshake → session key
        HandshakeSession session = establishHybridSession(clientId);

        // Step 2: Encrypt with AES-256-GCM using session key
        String ciphertext = encryptForSession(session.getSessionId(), plaintext);

        // Step 3: Decrypt and verify round-trip
        String decrypted  = decryptForSession(session.getSessionId(), ciphertext);
        boolean verified  = plaintext.equals(decrypted);

        long totalNs = System.nanoTime() - start;

        log.info("E2E pipeline [{}]: {} chars → {}B ciphertext → verified={} ({} ms)",
            session.getSessionId(), plaintext.length(),
            java.util.Base64.getDecoder().decode(ciphertext).length,
            verified, totalNs / 1_000_000);

        return new PipelineResult(
            session.toSummary(),
            plaintext.length(),
            java.util.Base64.getDecoder().decode(ciphertext).length,
            ciphertext,
            decrypted,
            verified,
            totalNs / 1_000_000.0
        );
    }

    // ─────────────────────────────────────────────────────────────
    // HELPERS
    // ─────────────────────────────────────────────────────────────

    private HandshakeSession getSessionOrThrow(String sessionId) {
        return orchestrator.getSession(sessionId)
            .orElseThrow(() -> new IllegalStateException(
                "Session not found: " + sessionId + ". Establish a session first."));
    }

    // ─────────────────────────────────────────────────────────────
    // DATA MODELS
    // ─────────────────────────────────────────────────────────────

    public record PipelineResult(
        HandshakeSession.SessionSummary session,
        int     plaintextBytes,
        int     ciphertextBytes,
        String  ciphertextBase64,
        String  decryptedText,
        boolean roundTripVerified,
        double  totalDurationMs
    ) {}
}
