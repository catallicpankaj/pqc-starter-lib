package com.pqc.hybrid.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

/**
 * ═══════════════════════════════════════════════════════════════════════
 * AES-256-GCM ENCRYPTION ENGINE
 * Wires the Kyber/Hybrid session key into actual data encryption.
 * ═══════════════════════════════════════════════════════════════════════
 *
 * This is the missing link between Phase 1 (key exchange) and real
 * end-to-end encryption. The session key produced by the hybrid handshake
 * becomes the AES-256 key used to encrypt and decrypt your actual data.
 *
 * WHY AES-256-GCM?
 *   - AES-256 is quantum-resistant (Grover's algorithm only halves
 *     effective key length: 256 → 128 bits, still unbreakable)
 *   - GCM mode provides both encryption AND authentication (AEAD)
 *     meaning tampering with ciphertext is detected automatically
 *   - NIST confirmed AES-256-GCM does NOT need replacement post-quantum
 *
 * WIRE FORMAT (EncryptedPayload):
 *   ┌─────────────────────────────────────────────────┐
 *   │  IV (12 bytes)  │  Ciphertext + GCM Tag (N+16)  │
 *   └─────────────────────────────────────────────────┘
 *
 * GCM TAG (16 bytes) is automatically appended by Java's AES/GCM/NoPadding.
 * Any bit flip in ciphertext causes decryption to throw AEADBadTagException.
 *
 * AAD (Additional Authenticated Data):
 *   Session ID is passed as AAD — it is authenticated but NOT encrypted.
 *   This binds the ciphertext to a specific session, preventing replay attacks
 *   where an attacker copies a ciphertext from session A into session B.
 */
@Component
public class AesGcmEngine {

    private static final Logger log = LoggerFactory.getLogger(AesGcmEngine.class);

    // AES-GCM constants — do not change these
    public static final int IV_LENGTH_BYTES  = 12;   // 96-bit IV — GCM recommended size
    public static final int TAG_LENGTH_BITS  = 128;  // 16-byte authentication tag
    public static final int KEY_LENGTH_BYTES = 32;   // 256-bit AES key

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final String BC        = "BC";

    private final SecureRandom secureRandom = new SecureRandom();

    static {
        if (Security.getProvider(BC) == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }

    // ─────────────────────────────────────────────────────────────
    // CORE ENCRYPT / DECRYPT
    // ─────────────────────────────────────────────────────────────

    /**
     * Encrypt plaintext using a 32-byte session key from the hybrid handshake.
     *
     * @param sessionKey  32-byte key from HandshakeSession.getSessionKeyMaterial()
     * @param plaintext   The data to encrypt (any bytes — JSON, binary, etc.)
     * @param sessionId   Used as AAD to bind ciphertext to this session
     * @return            EncryptedPayload containing IV + ciphertext + GCM tag
     */
    public EncryptedPayload encrypt(byte[] sessionKey, byte[] plaintext, String sessionId)
            throws Exception {

        validateKey(sessionKey);

        // Generate a fresh random IV for every encryption — NEVER reuse an IV with the same key
        byte[] iv = new byte[IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM, BC);
        cipher.init(Cipher.ENCRYPT_MODE,
            new SecretKeySpec(sessionKey, "AES"),
            new GCMParameterSpec(TAG_LENGTH_BITS, iv));

        // AAD: session ID binds this ciphertext to this specific session
        cipher.updateAAD(sessionId.getBytes());

        byte[] ciphertextWithTag = cipher.doFinal(plaintext);

        log.debug("AES-256-GCM encrypt: plaintext={}B → ciphertext={}B (IV={}B, tag=16B)",
            plaintext.length, ciphertextWithTag.length, iv.length);

        return new EncryptedPayload(iv, ciphertextWithTag, sessionId);
    }

    /**
     * Decrypt ciphertext using the same session key used to encrypt.
     *
     * Automatically verifies the GCM authentication tag — if the ciphertext
     * was tampered with in ANY way, this throws AEADBadTagException.
     *
     * @param sessionKey  Same 32-byte key used during encryption
     * @param payload     The EncryptedPayload returned by encrypt()
     * @return            Original plaintext bytes
     * @throws javax.crypto.AEADBadTagException if ciphertext was tampered with
     */
    public byte[] decrypt(byte[] sessionKey, EncryptedPayload payload) throws Exception {
        validateKey(sessionKey);

        Cipher cipher = Cipher.getInstance(ALGORITHM, BC);
        cipher.init(Cipher.DECRYPT_MODE,
            new SecretKeySpec(sessionKey, "AES"),
            new GCMParameterSpec(TAG_LENGTH_BITS, payload.iv()));

        // AAD must match exactly what was used during encryption
        cipher.updateAAD(payload.sessionId().getBytes());

        byte[] plaintext = cipher.doFinal(payload.ciphertextWithTag());

        log.debug("AES-256-GCM decrypt: ciphertext={}B → plaintext={}B",
            payload.ciphertextWithTag().length, plaintext.length);

        return plaintext;
    }

    // ─────────────────────────────────────────────────────────────
    // STRING CONVENIENCE METHODS
    // ─────────────────────────────────────────────────────────────

    /**
     * Encrypt a UTF-8 string (JSON payload, message, etc.)
     */
    public EncryptedPayload encryptString(byte[] sessionKey, String plaintext, String sessionId)
            throws Exception {
        return encrypt(sessionKey, plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8), sessionId);
    }

    /**
     * Decrypt back to a UTF-8 string.
     */
    public String decryptString(byte[] sessionKey, EncryptedPayload payload) throws Exception {
        return new String(decrypt(sessionKey, payload), java.nio.charset.StandardCharsets.UTF_8);
    }

    // ─────────────────────────────────────────────────────────────
    // SERIALIZATION — for sending over HTTP / storing
    // ─────────────────────────────────────────────────────────────

    /**
     * Serialize EncryptedPayload to a single Base64 string safe for HTTP headers/JSON.
     *
     * Wire format: Base64(IV || CiphertextWithTag)
     * Session ID is sent separately (e.g. X-PQC-Session-Id header).
     */
    public String toBase64Wire(EncryptedPayload payload) {
        byte[] wire = new byte[payload.iv().length + payload.ciphertextWithTag().length];
        System.arraycopy(payload.iv(),              0, wire, 0,                    payload.iv().length);
        System.arraycopy(payload.ciphertextWithTag(), 0, wire, payload.iv().length, payload.ciphertextWithTag().length);
        return java.util.Base64.getEncoder().encodeToString(wire);
    }

    /**
     * Deserialize from Base64 wire format back to EncryptedPayload.
     */
    public EncryptedPayload fromBase64Wire(String base64, String sessionId) {
        byte[] wire = java.util.Base64.getDecoder().decode(base64);
        byte[] iv   = Arrays.copyOfRange(wire, 0, IV_LENGTH_BYTES);
        byte[] ct   = Arrays.copyOfRange(wire, IV_LENGTH_BYTES, wire.length);
        return new EncryptedPayload(iv, ct, sessionId);
    }

    // ─────────────────────────────────────────────────────────────
    // VALIDATION
    // ─────────────────────────────────────────────────────────────

    private void validateKey(byte[] key) {
        if (key == null || key.length != KEY_LENGTH_BYTES) {
            throw new IllegalArgumentException(
                "AES-256-GCM requires exactly 32-byte key, got: " +
                (key == null ? "null" : key.length + " bytes"));
        }
    }

    // ─────────────────────────────────────────────────────────────
    // DATA MODEL
    // ─────────────────────────────────────────────────────────────

    /**
     * Holds the full output of an AES-256-GCM encryption operation.
     *
     * iv               — 12-byte random nonce, must be sent with the ciphertext
     * ciphertextWithTag — encrypted data + 16-byte GCM authentication tag
     * sessionId        — the session this ciphertext is bound to (via AAD)
     */
    public record EncryptedPayload(
        byte[] iv,
        byte[] ciphertextWithTag,
        String sessionId
    ) {
        public int totalBytes()      { return iv.length + ciphertextWithTag.length; }
        public int plaintextBytes()  { return ciphertextWithTag.length - (TAG_LENGTH_BITS / 8); }

        /**
         * Records' auto-generated equals()/hashCode() compare byte[] components by
         * reference, not by content — overridden so two payloads with the same
         * IV/ciphertext bytes compare equal.
         */
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof EncryptedPayload other)) return false;
            return Arrays.equals(iv, other.iv)
                && Arrays.equals(ciphertextWithTag, other.ciphertextWithTag)
                && java.util.Objects.equals(sessionId, other.sessionId);
        }

        @Override
        public int hashCode() {
            int result = java.util.Objects.hash(sessionId);
            result = 31 * result + Arrays.hashCode(iv);
            result = 31 * result + Arrays.hashCode(ciphertextWithTag);
            return result;
        }
    }
}
