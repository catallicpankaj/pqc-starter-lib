package com.pqc.hybrid.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.pqc.hybrid.handshake.ClientCapability;
import com.pqc.hybrid.handshake.HandshakeSession;
import com.pqc.hybrid.handshake.HybridHandshakeOrchestrator;
import com.pqc.hybrid.handshake.KyberKemEngine;

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
 * USAGE — session-based (both sides share a live HandshakeSession, single JVM today):
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
 *
 * USAGE — public-key-addressed (no session; encrypt directly to a known recipient's Kyber public
 * key — the shape needed for real cross-service messaging or at-rest field encryption):
 *
 *   PqcEncryptedPayload encrypted = pqcEncryption.encrypt(data, recipientPublicKey);
 *   byte[] plaintext              = pqcEncryption.decrypt(encrypted, myPrivateKey);
 */
@Service
public class PqcEncryptionService {

    private static final Logger log = LoggerFactory.getLogger(PqcEncryptionService.class);

    /**
     * Fixed AAD for the public-key-addressed encrypt()/decrypt() methods below. Unlike the
     * session-based flow (where AAD is the session ID, binding ciphertext to a specific live
     * session to stop cross-session replay), there is no session concept here — each encryption
     * already uses a fresh, single-use Kyber shared secret, so AAD isn't load-bearing for replay
     * protection. A fixed constant satisfies AesGcmEngine's AAD parameter and labels the format.
     */
    private static final String PUBLIC_KEY_AAD = "pqc-encrypted-payload";

    private final HybridHandshakeOrchestrator orchestrator;
    private final AesGcmEngine                aesGcm;
    private final KyberKemEngine              kyberEngine;

    public PqcEncryptionService(HybridHandshakeOrchestrator orchestrator, AesGcmEngine aesGcm,
                                 KyberKemEngine kyberEngine) {
        this.orchestrator = orchestrator;
        this.aesGcm       = aesGcm;
        this.kyberEngine  = kyberEngine;
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
    // PUBLIC-KEY-ADDRESSED ENCRYPTION — no session, no prior handshake
    // ─────────────────────────────────────────────────────────────
    //
    // Unlike encryptForSession()/decryptForSession() above (which require both sides to share
    // a live, previously-established HandshakeSession — only possible within one JVM today),
    // these methods encrypt directly to a known recipient's Kyber-768 public key. There is no
    // session state: the recipient only needs their own private key to decrypt, regardless of
    // where or when the ciphertext arrives. This is the shape needed for actual cross-service
    // messaging, at-rest field encryption, or any store-and-forward use case.
    //
    // Kyber-768 encapsulate() itself produces a fresh, single-use shared secret per call — that
    // 32-byte secret is used directly as the AES-256 key (standard KEM/DEM composition; no
    // additional KDF step needed for a one-time secret this size).

    /**
     * Encrypt data to a recipient's Kyber-768 public key. No session or prior handshake required —
     * the recipient can decrypt with only their matching private key, whenever the ciphertext
     * arrives.
     *
     * @param data               plaintext bytes to encrypt
     * @param recipientPublicKey recipient's Kyber-768 public key
     * @return                   a {@link PqcEncryptedPayload} carrying everything the recipient
     *                           needs to decrypt — safe to serialize as JSON (e.g. a
     *                           {@code @RequestBody}) or via {@link PqcEncryptedPayload#toBytes()}
     */
    public PqcEncryptedPayload encrypt(byte[] data, PublicKey recipientPublicKey) throws Exception {
        KyberKemEngine.KemResult kem = kyberEngine.encapsulate(recipientPublicKey);
        AesGcmEngine.EncryptedPayload aesPayload =
            aesGcm.encrypt(kem.sharedSecret(), data, PUBLIC_KEY_AAD);

        log.debug("encrypt(recipientPublicKey): {} bytes → {} byte encapsulated key + {} byte ciphertext",
            data.length, kem.ciphertext().length, aesPayload.ciphertextWithTag().length);

        return new PqcEncryptedPayload(kem.ciphertext(), aesPayload.iv(), aesPayload.ciphertextWithTag());
    }

    /**
     * Convenience: {@link #encrypt(byte[], PublicKey)} but returns the serialized wire bytes
     * directly ({@code PqcEncryptedPayload.toBytes()}) — for callers storing ciphertext as a
     * single blob (e.g. a database column) rather than working with the structured payload.
     */
    public byte[] encryptToBytes(byte[] data, PublicKey recipientPublicKey) throws Exception {
        return encrypt(data, recipientPublicKey).toBytes();
    }

    /**
     * Decrypt a {@link PqcEncryptedPayload} with the matching Kyber-768 private key.
     * Automatically verifies the GCM authentication tag — throws if the payload was tampered with
     * or the private key does not match the public key it was encrypted to.
     */
    public byte[] decrypt(PqcEncryptedPayload payload, PrivateKey privateKey) throws Exception {
        byte[] sharedSecret = kyberEngine.decapsulate(privateKey, payload.encapsulatedKey());
        AesGcmEngine.EncryptedPayload aesPayload =
            new AesGcmEngine.EncryptedPayload(payload.iv(), payload.ciphertext(), PUBLIC_KEY_AAD);
        byte[] plaintext = aesGcm.decrypt(sharedSecret, aesPayload);

        log.debug("decrypt(privateKey): {} byte ciphertext → {} bytes",
            payload.ciphertext().length, plaintext.length);

        return plaintext;
    }

    /**
     * Convenience: decrypt from the serialized wire bytes produced by
     * {@link PqcEncryptedPayload#toBytes()} / {@link #encryptToBytes(byte[], PublicKey)}.
     */
    public byte[] decrypt(byte[] serializedPayload, PrivateKey privateKey) throws Exception {
        return decrypt(PqcEncryptedPayload.fromBytes(serializedPayload), privateKey);
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
