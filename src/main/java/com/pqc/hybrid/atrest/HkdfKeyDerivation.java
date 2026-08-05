package com.pqc.hybrid.atrest;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import java.nio.charset.StandardCharsets;

/**
 * HKDF-SHA256 per-record key derivation for data-at-rest encryption (RFC 5869).
 *
 * Derives a unique 256-bit AES key for every (masterKey, recordId, fieldName, keyVersion)
 * tuple so that compromising one record's key does not expose others.
 *
 * Derivation formula:
 *   recordKey = HKDF-SHA256(
 *       inputKeyMaterial = masterKey,
 *       salt             = recordId bytes,
 *       info             = "fieldName:keyVersion" bytes
 *   )
 *
 * Security properties:
 *   - Different recordId → different salt → independent keys for each row
 *   - Different fieldName → different info → independent keys for each column
 *   - Different keyVersion → different info → old and new keys are unrelated
 *   - HKDF output is pseudo-random — knowing one derived key reveals nothing about others
 *
 * HKDF is standardised in RFC 5869 and is NIST-recommended for key derivation.
 * BouncyCastle's HKDFBytesGenerator is used as the underlying implementation.
 */
public class HkdfKeyDerivation {

    private static final int KEY_LENGTH_BYTES = 32; // 256-bit AES key

    /**
     * Derive a 256-bit AES key for a specific record field and key version.
     *
     * @param masterKey   32-byte master key (from KMS or ephemeral)
     * @param recordId    unique identifier for the record (e.g. entity primary key)
     * @param fieldName   name of the field being encrypted (e.g. "ssn", "diagnosisCode")
     * @param keyVersion  current master key version (increments on rotation)
     * @return 32-byte derived key specific to this (record, field, version) triple
     */
    public byte[] deriveFieldKey(byte[] masterKey, String recordId,
                                  String fieldName, int keyVersion) {
        byte[] salt = recordId.getBytes(StandardCharsets.UTF_8);
        byte[] info = (fieldName + ":" + keyVersion).getBytes(StandardCharsets.UTF_8);

        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(masterKey, salt, info));

        byte[] derived = new byte[KEY_LENGTH_BYTES];
        hkdf.generateBytes(derived, 0, KEY_LENGTH_BYTES);
        return derived;
    }

    /**
     * Convenience overload — derives a key using a String-based recordId
     * composed from multiple ID parts (e.g. composite primary keys).
     *
     * @param masterKey  32-byte master key
     * @param recordId   composite record identifier (joined with "|")
     * @param fieldName  field name
     * @param keyVersion key version
     * @return 32-byte derived key
     */
    public byte[] deriveFieldKey(byte[] masterKey, String[] recordId,
                                  String fieldName, int keyVersion) {
        return deriveFieldKey(masterKey, String.join("|", recordId), fieldName, keyVersion);
    }
}
