package com.pqc.hybrid.atrest;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Top-level Data-at-Rest encryption service — Phase 6 public API.
 *
 * Combines all at-rest encryption capabilities into a single injectable service:
 *   - Field-level encryption (JPA column values)
 *   - Streaming file encryption (InputStream → OutputStream)
 *   - Re-encryption for key rotation
 *
 * Usage:
 * <pre>{@code
 * @Autowired AtRestEncryptionService atRest;
 *
 * // Field encryption (JPA)
 * String stored  = atRest.encryptField("123-45-6789", "patient-42", "ssn");
 * String plaintext = atRest.decryptField(stored, "patient-42", "ssn");
 *
 * // File encryption
 * try (InputStream in  = new FileInputStream("report.pdf");
 *      OutputStream out = new FileOutputStream("report.enc")) {
 *     atRest.encryptFile(in, out);
 * }
 *
 * // Key rotation re-encryption
 * String rekeyed = atRest.reEncryptIfNeeded(stored, "patient-42", "ssn");
 * }</pre>
 */
public class AtRestEncryptionService {

    private final EncryptedFieldService  fieldService;
    private final StreamingAesGcmEngine  streamEngine;
    private final ReEncryptionService    reEncService;

    public AtRestEncryptionService(EncryptedFieldService fieldService,
                                    StreamingAesGcmEngine streamEngine,
                                    ReEncryptionService reEncService) {
        this.fieldService = fieldService;
        this.streamEngine = streamEngine;
        this.reEncService = reEncService;
    }

    // ─────────────────────────────────────────────────────────────
    // FIELD ENCRYPTION (JPA / DB columns)
    // ─────────────────────────────────────────────────────────────

    /**
     * Encrypt a plaintext string for storage in a database column.
     * Uses HKDF per-record key isolation.
     *
     * @param plaintext  sensitive field value
     * @param recordId   owning record identifier (e.g. primary key as String)
     * @param fieldName  field/column name (e.g. "ssn", "diagnosisCode")
     * @return           versioned encoded string ("v{n}:base64...")
     */
    public String encryptField(String plaintext, String recordId, String fieldName)
            throws Exception {
        return fieldService.encryptField(plaintext, recordId, fieldName);
    }

    /**
     * Decrypt a stored encoded field value back to plaintext.
     * Automatically reads key version from the "v{n}:" prefix.
     */
    public String decryptField(String encoded, String recordId, String fieldName)
            throws Exception {
        return fieldService.decryptField(encoded, recordId, fieldName);
    }

    // ─────────────────────────────────────────────────────────────
    // FILE / STREAM ENCRYPTION
    // ─────────────────────────────────────────────────────────────

    /**
     * Encrypt an InputStream to an OutputStream using chunked AES-256-GCM.
     * Suitable for files of any size — memory usage is bounded by chunk size (4 KB).
     *
     * @param fileKey    32-byte key for file encryption (derive via HKDF or use a session key)
     * @param plaintext  source stream (file, S3 object, memory buffer)
     * @param ciphertext destination stream
     */
    public void encryptFile(byte[] fileKey, InputStream plaintext, OutputStream ciphertext)
            throws Exception {
        streamEngine.encryptStream(fileKey, plaintext, ciphertext);
    }

    /**
     * Decrypt a stream produced by {@link #encryptFile}.
     *
     * @param fileKey    same 32-byte key used during encryption
     * @param ciphertext encrypted source stream
     * @param plaintext  decrypted destination stream
     */
    public void decryptFile(byte[] fileKey, InputStream ciphertext, OutputStream plaintext)
            throws Exception {
        streamEngine.decryptStream(fileKey, ciphertext, plaintext);
    }

    /**
     * Convenience: encrypt a byte array, returns encrypted bytes.
     */
    public byte[] encryptBytes(byte[] fileKey, byte[] data) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        streamEngine.encryptStream(fileKey, new ByteArrayInputStream(data), out);
        return out.toByteArray();
    }

    /**
     * Convenience: decrypt a byte array, returns plaintext bytes.
     */
    public byte[] decryptBytes(byte[] fileKey, byte[] encrypted) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        streamEngine.decryptStream(fileKey, new ByteArrayInputStream(encrypted), out);
        return out.toByteArray();
    }

    // ─────────────────────────────────────────────────────────────
    // KEY ROTATION / RE-ENCRYPTION
    // ─────────────────────────────────────────────────────────────

    /**
     * Re-encrypt a field value under the current master key version.
     * Use this in a batch job after key rotation, or lazily on each READ.
     */
    public String reEncryptField(String encoded, String recordId, String fieldName)
            throws Exception {
        return reEncService.reEncryptField(encoded, recordId, fieldName);
    }

    /**
     * Re-encrypt only if the value is older than the current key version.
     * Efficient for lazy re-encryption on read.
     */
    public String reEncryptIfNeeded(String encoded, String recordId, String fieldName)
            throws Exception {
        return reEncService.reEncryptIfNeeded(encoded, recordId, fieldName);
    }

    /** Returns true if the stored value needs re-encryption (older key version). */
    public boolean needsReEncryption(String encoded) {
        return reEncService.needsReEncryption(encoded);
    }

    /** Current master key version — used for "v{n}:" prefix on new encryptions. */
    public int getMasterKeyVersion() {
        return fieldService.getMasterKeyVersion();
    }
}
