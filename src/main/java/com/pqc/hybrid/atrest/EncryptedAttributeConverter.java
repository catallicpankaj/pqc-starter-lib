package com.pqc.hybrid.atrest;

import jakarta.persistence.AttributeConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstract JPA {@link AttributeConverter} base class for transparent field encryption.
 *
 * Extend this class in your JPA application to create a concrete converter
 * for each encrypted field type. Then annotate JPA fields with
 * {@code @Convert(converter = YourConverter.class)}.
 *
 * Example usage in a JPA application:
 *
 * <pre>{@code
 * // 1. Define a converter per field (or reuse one converter for all fields)
 * @Converter
 * public class SsnConverter extends EncryptedAttributeConverter {
 *     @Autowired EncryptedFieldService service;
 *
 *     @Override protected EncryptedFieldService getService()  { return service; }
 *     @Override protected String getFieldName()               { return "ssn"; }
 *     @Override protected String getRecordId()                {
 *         // JPA's AttributeConverter never gives converters access to the owning
 *         // entity, so a stable recordId usually means using a value the converter
 *         // itself can reach — e.g. inject a request/session-scoped bean that holds
 *         // the current record's ID, or accept reduced (all-rows-share-a-key)
 *         // isolation by leaving this method at its default (returns getFieldName()).
 *         return currentPatientId.get();
 *     }
 * }
 *
 * // 2. Annotate your entity field
 * @Entity
 * public class PatientRecord {
 *     @Id private Long id;
 *
 *     @EncryptedField
 *     @Convert(converter = SsnConverter.class)
 *     @Column(length = 512)   // encrypted value is longer than plaintext
 *     private String ssn;
 * }
 * }</pre>
 *
 * Why abstract instead of a single universal converter?
 * - Each field needs a different {@code fieldName} for key isolation via HKDF.
 *   Two fields on the same record encrypted under the same key would be a
 *   security regression — HKDF's purpose is to prevent this.
 * - The {@code recordId} must come from the entity — a converter cannot access
 *   the entity's primary key without extra wiring, so it is left to subclasses.
 *
 * For a simpler setup where record isolation is not required (e.g., lookup tables),
 * use a fixed recordId such as the table name.
 */
public abstract class EncryptedAttributeConverter implements AttributeConverter<String, String> {

    private static final Logger log = LoggerFactory.getLogger(EncryptedAttributeConverter.class);

    // ─────────────────────────────────────────────────────────────
    // Abstract contract — implement in each concrete converter
    // ─────────────────────────────────────────────────────────────

    /**
     * Return the {@link EncryptedFieldService} instance (typically @Autowired).
     */
    protected abstract EncryptedFieldService getService();

    /**
     * Return the logical field name used for HKDF key isolation.
     * Must be stable — changing it changes the derived key and makes
     * existing encrypted values unreadable.
     */
    protected abstract String getFieldName();

    /**
     * Return a stable identifier for the owning record.
     * Override when you need per-row key isolation (recommended for sensitive data).
     * Default: returns the field name (row-level isolation disabled — all rows share a key).
     */
    protected String getRecordId() {
        return getFieldName();
    }

    // ─────────────────────────────────────────────────────────────
    // AttributeConverter implementation
    // ─────────────────────────────────────────────────────────────

    /**
     * Called by JPA before INSERT / UPDATE — encrypts the plaintext field value.
     * Returns null if the attribute is null (null is stored as null in the DB).
     */
    @Override
    public String convertToDatabaseColumn(String attribute) {
        if (attribute == null) return null;
        try {
            return getService().encryptField(attribute, getRecordId(), getFieldName());
        } catch (Exception e) {
            log.error("Failed to encrypt field '{}': {}", getFieldName(), e.getMessage());
            throw new RuntimeException("Field encryption failed for: " + getFieldName(), e);
        }
    }

    /**
     * Called by JPA after SELECT — decrypts the stored encoded value back to plaintext.
     * Returns null if the column value is null.
     */
    @Override
    public String convertToEntityAttribute(String dbData) {
        if (dbData == null) return null;
        try {
            return getService().decryptField(dbData, getRecordId(), getFieldName());
        } catch (Exception e) {
            log.error("Failed to decrypt field '{}': {}", getFieldName(), e.getMessage());
            throw new RuntimeException("Field decryption failed for: " + getFieldName(), e);
        }
    }
}
