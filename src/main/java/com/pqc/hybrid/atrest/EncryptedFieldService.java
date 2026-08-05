package com.pqc.hybrid.atrest;

import com.pqc.hybrid.crypto.AesGcmEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * High-level at-rest field encryption service.
 *
 * Combines HKDF per-record key derivation with AES-256-GCM encryption
 * to produce per-field, per-record, per-version encrypted strings safe
 * for storage in a database column.
 *
 * Stored format:
 *   v{keyVersion}:{Base64(IV || Ciphertext+GCM-Tag)}
 *
 * Examples:
 *   v1:aGVsbG8gd29ybGQ...   ← encrypted with key version 1
 *   v2:d29ybGQgaGVsbG8...   ← re-encrypted after key rotation to version 2
 *
 * The "v{n}:" prefix allows the decryption side to know which master key
 * version was used without storing it separately. On rotation, old values
 * with "v1:" are lazily or eagerly re-encrypted to "v2:".
 *
 * Key isolation:
 *   recordKey = HKDF(masterKey, salt=recordId, info="fieldName:version")
 *   A leak of one field's derived key does NOT expose any other field or record.
 */
public class EncryptedFieldService {

    private static final Logger log = LoggerFactory.getLogger(EncryptedFieldService.class);
    private static final String VERSION_PREFIX = "v";
    private static final String SEPARATOR      = ":";

    private final AesGcmEngine      aesGcm;
    private final HkdfKeyDerivation hkdf;
    private final byte[]            masterKey;
    private final int               masterKeyVersion;

    public EncryptedFieldService(AesGcmEngine aesGcm, HkdfKeyDerivation hkdf,
                                  byte[] masterKey, int masterKeyVersion) {
        if (masterKey.length != 32)
            throw new IllegalArgumentException("Master key must be 32 bytes, got: " + masterKey.length);
        this.aesGcm          = aesGcm;
        this.hkdf            = hkdf;
        this.masterKey       = masterKey;
        this.masterKeyVersion = masterKeyVersion;
    }

    // ─────────────────────────────────────────────────────────────
    // ENCRYPT / DECRYPT
    // ─────────────────────────────────────────────────────────────

    /**
     * Encrypt a plaintext string for storage in a database column.
     *
     * @param plaintext  the sensitive field value (e.g. SSN, diagnosis code)
     * @param recordId   unique identifier of the owning record (e.g. entity primary key)
     * @param fieldName  name of the field (e.g. "ssn", "diagnosisCode")
     * @return           versioned encoded string safe for database storage
     */
    public String encryptField(String plaintext, String recordId, String fieldName)
            throws Exception {
        return encryptField(plaintext, recordId, fieldName, masterKeyVersion);
    }

    /**
     * Encrypt using a specific key version (used by ReEncryptionService).
     */
    public String encryptField(String plaintext, String recordId,
                                String fieldName, int keyVersion) throws Exception {
        byte[] fieldKey = hkdf.deriveFieldKey(masterKey, recordId, fieldName, keyVersion);

        // Use "recordId:fieldName:version" as AAD to bind ciphertext to its context
        String aad = recordId + ":" + fieldName + ":" + keyVersion;
        AesGcmEngine.EncryptedPayload payload =
                aesGcm.encryptString(fieldKey, plaintext, aad);

        // Wire: Base64(IV || Ciphertext+Tag)
        String base64 = aesGcm.toBase64Wire(payload);
        String encoded = VERSION_PREFIX + keyVersion + SEPARATOR + base64;

        log.debug("encryptField: recordId={} field={} version={} encLen={}",
                recordId, fieldName, keyVersion, encoded.length());
        return encoded;
    }

    /**
     * Decrypt a stored encoded value back to plaintext.
     * Automatically reads the key version from the "v{n}:" prefix.
     *
     * @param encoded   the stored string (format: "v{n}:base64...")
     * @param recordId  same recordId used during encryption
     * @param fieldName same fieldName used during encryption
     * @return          original plaintext
     */
    public String decryptField(String encoded, String recordId, String fieldName)
            throws Exception {
        int version = parseVersion(encoded);
        return decryptField(encoded, recordId, fieldName, version);
    }

    /**
     * Decrypt using an explicit key version (used by ReEncryptionService).
     */
    public String decryptField(String encoded, String recordId,
                                String fieldName, int keyVersion) throws Exception {
        String base64 = stripVersionPrefix(encoded, keyVersion);
        byte[] fieldKey = hkdf.deriveFieldKey(masterKey, recordId, fieldName, keyVersion);

        String aad = recordId + ":" + fieldName + ":" + keyVersion;
        AesGcmEngine.EncryptedPayload payload = aesGcm.fromBase64Wire(base64, aad);

        String plaintext = aesGcm.decryptString(fieldKey, payload);
        log.debug("decryptField: recordId={} field={} version={}", recordId, fieldName, keyVersion);
        return plaintext;
    }

    // ─────────────────────────────────────────────────────────────
    // VERSION HELPERS
    // ─────────────────────────────────────────────────────────────

    /**
     * Returns true if the encoded value was encrypted with a different key version
     * than the current master key version. Such values should be re-encrypted.
     */
    public boolean needsReEncryption(String encoded) {
        return parseVersion(encoded) != masterKeyVersion;
    }

    public int getMasterKeyVersion() { return masterKeyVersion; }

    public int parseVersion(String encoded) {
        if (encoded == null || !encoded.startsWith(VERSION_PREFIX))
            throw new IllegalArgumentException("Invalid encoded field — missing version prefix: " + encoded);
        int sep = encoded.indexOf(SEPARATOR);
        if (sep < 2)
            throw new IllegalArgumentException("Invalid encoded field — missing separator: " + encoded);
        return Integer.parseInt(encoded.substring(1, sep));
    }

    private String stripVersionPrefix(String encoded, int version) {
        String prefix = VERSION_PREFIX + version + SEPARATOR;
        if (!encoded.startsWith(prefix))
            throw new IllegalArgumentException(
                    "Encoded value does not have expected prefix '" + prefix + "': " + encoded);
        return encoded.substring(prefix.length());
    }
}
