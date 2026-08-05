package com.pqc.hybrid.atrest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Re-encryption service for master key rotation.
 *
 * When the master key is rotated (V1 → V2), all existing database values
 * that were encrypted under V1 must be re-encrypted under V2. This service
 * handles that migration — field by field, record by record.
 *
 * Two re-encryption strategies:
 *
 *   LAZY  — re-encrypt on the next READ: read V1 ciphertext, decrypt,
 *            immediately re-encrypt with V2, write back to DB before returning.
 *            Zero-downtime, no batch job, but each record gets migrated
 *            only when it is first accessed after rotation.
 *
 *   EAGER — run {@link #reEncryptField} in a batch job over all records.
 *            Ensures full migration within a defined time window (e.g. 30 days).
 *            Required by compliance frameworks (PCI-DSS, HIPAA) that mandate
 *            a maximum transition window after key rotation.
 *
 * Both strategies produce identical output — the difference is timing.
 *
 * Safety:
 *   - Re-encryption is a decrypt(old) → encrypt(new) operation in memory.
 *   - The old key is never deleted until re-encryption is complete for all records.
 *   - The {@link #needsReEncryption(String)} check lets callers skip records
 *     that were already migrated.
 */
public class ReEncryptionService {

    private static final Logger log = LoggerFactory.getLogger(ReEncryptionService.class);

    /** Service holding the CURRENT (new) master key — used for re-encryption. */
    private final EncryptedFieldService currentService;
    /**
     * Service holding the PREVIOUS (old) master key — used to decrypt old values.
     * If no key rotation has occurred, this is the same instance as {@code currentService}.
     */
    private final EncryptedFieldService previousService;

    /**
     * Single-key constructor — use when there is no in-flight key rotation.
     * Both decryption and re-encryption use the same master key.
     */
    public ReEncryptionService(EncryptedFieldService fieldService) {
        this(fieldService, fieldService);
    }

    /**
     * Dual-key constructor — use during key rotation.
     * {@code previousService} decrypts old values; {@code currentService} re-encrypts.
     *
     * @param previousService service configured with the OLD master key (for decryption)
     * @param currentService  service configured with the NEW master key (for re-encryption)
     */
    public ReEncryptionService(EncryptedFieldService previousService,
                                EncryptedFieldService currentService) {
        this.previousService = previousService;
        this.currentService  = currentService;
    }

    // ─────────────────────────────────────────────────────────────
    // PUBLIC API
    // ─────────────────────────────────────────────────────────────

    /**
     * Re-encrypt a single stored field value from an old key version to the current one.
     *
     * Steps:
     *   1. Parse old key version from the "v{n}:" prefix.
     *   2. Decrypt using HKDF-derived key for (recordId, fieldName, oldVersion).
     *   3. Re-encrypt using HKDF-derived key for (recordId, fieldName, newVersion).
     *   4. Return new encoded string with updated "v{newVersion}:" prefix.
     *
     * @param encoded    stored encoded value (format: "v{oldVersion}:base64...")
     * @param recordId   record identifier (same used during original encryption)
     * @param fieldName  field name (same used during original encryption)
     * @return           new encoded value with current key version prefix
     */
    public String reEncryptField(String encoded, String recordId, String fieldName)
            throws Exception {
        int oldVersion = previousService.parseVersion(encoded);
        int newVersion = currentService.getMasterKeyVersion();

        if (oldVersion == newVersion) {
            log.debug("reEncryptField: already at version {} — skipping", newVersion);
            return encoded;
        }

        log.info("reEncryptField: recordId={} field={} v{}→v{}", recordId, fieldName, oldVersion, newVersion);

        String plaintext = previousService.decryptField(encoded, recordId, fieldName, oldVersion);
        return currentService.encryptField(plaintext, recordId, fieldName, newVersion);
    }

    /**
     * Returns true if the encoded value was encrypted with a key version
     * older than the current master key version and should be re-encrypted.
     *
     * Use this for lazy re-encryption: on each read, check this flag and
     * re-encrypt + write back if true.
     */
    public boolean needsReEncryption(String encoded) {
        return currentService.needsReEncryption(encoded);
    }

    /**
     * Convenience: re-encrypt only if needed.
     * Returns the original value if it is already at the current key version.
     *
     * @return re-encrypted value (current version) or original (if already current)
     */
    public String reEncryptIfNeeded(String encoded, String recordId, String fieldName)
            throws Exception {
        if (!needsReEncryption(encoded)) return encoded;
        return reEncryptField(encoded, recordId, fieldName);
    }
}
