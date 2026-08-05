package com.pqc.hybrid.atrest.annotation;

import java.lang.annotation.*;

/**
 * Marks a JPA entity field for transparent AES-256-GCM encryption at rest.
 *
 * Usage — add to any String field on a JPA entity alongside
 * {@code @Convert(converter = YourConverter.class)}:
 *
 * <pre>{@code
 * @Entity
 * public class PatientRecord {
 *
 *     @Id
 *     private Long id;
 *
 *     @EncryptedField
 *     @Convert(converter = SsnConverter.class)
 *     @Column(length = 512)    // encrypted value is longer than plaintext
 *     private String ssn;
 *
 *     @EncryptedField
 *     @Convert(converter = DiagnosisConverter.class)
 *     @Column(length = 512)
 *     private String diagnosisCode;
 * }
 * }</pre>
 *
 * The converter handles the actual encryption/decryption via
 * {@link com.pqc.hybrid.atrest.EncryptedAttributeConverter}.
 *
 * Each field gets a UNIQUE derived key via HKDF-SHA256:
 *   {@code recordKey = HKDF(masterKey, recordId, fieldName, keyVersion)}
 *
 * Compromising one field's key does NOT expose other fields or records.
 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface EncryptedField {

    /**
     * Human-readable description of the sensitivity level.
     * Used for audit logs and documentation only — no runtime effect.
     */
    String sensitivity() default "CONFIDENTIAL";
}
