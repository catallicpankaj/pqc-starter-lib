package com.pqc.hybrid.atrest;

import com.pqc.hybrid.crypto.AesGcmEngine;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.*;

import java.security.SecureRandom;
import java.security.Security;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for {@link EncryptedAttributeConverter} — the abstract JPA converter base class.
 * No other test exercises its actual convertToDatabaseColumn()/convertToEntityAttribute()
 * logic directly (only the EncryptedFieldService it delegates to is tested elsewhere),
 * so null handling and exception wrapping here had zero prior coverage.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class EncryptedAttributeConverterTest {

    private static EncryptedFieldService fieldService;

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BC") == null) Security.insertProviderAt(new BouncyCastleProvider(), 1);
        byte[] masterKey = new byte[32];
        new SecureRandom().nextBytes(masterKey);
        fieldService = new EncryptedFieldService(new AesGcmEngine(), new HkdfKeyDerivation(), masterKey, 1);
    }

    /** Default getRecordId() — row isolation disabled, all rows for this field share a key. */
    static class SsnConverter extends EncryptedAttributeConverter {
        @Override protected EncryptedFieldService getService()  { return fieldService; }
        @Override protected String               getFieldName() { return "ssn"; }
    }

    /** Overrides getRecordId() to demonstrate per-row key isolation. */
    static class PerRowConverter extends EncryptedAttributeConverter {
        String recordId = "row-default";
        @Override protected EncryptedFieldService getService()  { return fieldService; }
        @Override protected String               getFieldName() { return "diagnosisCode"; }
        @Override protected String               getRecordId()  { return recordId; }
    }

    /** A converter whose service always throws — verifies exception wrapping. */
    static class FailingConverter extends EncryptedAttributeConverter {
        @Override protected EncryptedFieldService getService() {
            return new EncryptedFieldService(new AesGcmEngine(), new HkdfKeyDerivation(), new byte[16], 1); // wrong key length -> throws
        }
        @Override protected String getFieldName() { return "boom"; }
    }

    @Test @Order(1)
    @DisplayName("convertToDatabaseColumn / convertToEntityAttribute round-trip recovers the original plaintext")
    void roundTrip() {
        SsnConverter converter = new SsnConverter();
        String stored = converter.convertToDatabaseColumn("123-45-6789");
        assertThat(stored).startsWith("v1:");

        String recovered = converter.convertToEntityAttribute(stored);
        assertThat(recovered).isEqualTo("123-45-6789");
        System.out.println("✓ Converter round-trip: plaintext -> " + stored + " -> plaintext");
    }

    @Test @Order(2)
    @DisplayName("convertToDatabaseColumn(null) returns null — nulls are stored as null, not encrypted")
    void nullAttributeReturnsNull() {
        assertThat(new SsnConverter().convertToDatabaseColumn(null)).isNull();
        System.out.println("✓ convertToDatabaseColumn(null) -> null");
    }

    @Test @Order(3)
    @DisplayName("convertToEntityAttribute(null) returns null — a null DB column stays null")
    void nullDbDataReturnsNull() {
        assertThat(new SsnConverter().convertToEntityAttribute(null)).isNull();
        System.out.println("✓ convertToEntityAttribute(null) -> null");
    }

    @Test @Order(4)
    @DisplayName("Default getRecordId() returns getFieldName() — two different SsnConverter instances share a key")
    void defaultRecordIdIsFieldName() {
        String stored1 = new SsnConverter().convertToDatabaseColumn("111-11-1111");
        String stored2 = new SsnConverter().convertToDatabaseColumn("111-11-1111");
        // Different instances, same field, default (row-isolation-disabled) recordId -- an
        // instance created fresh must still be able to decrypt the other's ciphertext.
        String recovered = new SsnConverter().convertToEntityAttribute(stored1);
        assertThat(recovered).isEqualTo("111-11-1111");
        assertThat(stored1).isNotEqualTo(stored2); // still randomised by IV, just same key
        System.out.println("✓ Default getRecordId(): any SsnConverter instance can decrypt any other's ciphertext");
    }

    @Test @Order(5)
    @DisplayName("Overriding getRecordId() gives real per-row key isolation")
    void perRowIsolationWhenRecordIdOverridden() {
        PerRowConverter forRow1 = new PerRowConverter();
        forRow1.recordId = "patient-1";
        String storedForRow1 = forRow1.convertToDatabaseColumn("diagnosis-A");

        PerRowConverter forRow2 = new PerRowConverter();
        forRow2.recordId = "patient-2";

        // A converter configured for a DIFFERENT recordId must NOT be able to decrypt
        // row 1's ciphertext -- this is exactly what per-row key isolation guarantees.
        assertThatThrownBy(() -> forRow2.convertToEntityAttribute(storedForRow1))
            .isInstanceOf(RuntimeException.class);

        // The matching recordId still works correctly.
        PerRowConverter alsoRow1 = new PerRowConverter();
        alsoRow1.recordId = "patient-1";
        assertThat(alsoRow1.convertToEntityAttribute(storedForRow1)).isEqualTo("diagnosis-A");
        System.out.println("✓ getRecordId() override: row 2's converter cannot decrypt row 1's value");
    }

    @Test @Order(6)
    @DisplayName("Encryption failure is wrapped in a RuntimeException naming the field")
    void encryptionFailureWrapsException() {
        assertThatThrownBy(() -> new FailingConverter().convertToDatabaseColumn("data"))
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("boom");
        System.out.println("✓ Underlying failure wrapped in RuntimeException naming the field");
    }

    @Test @Order(7)
    @DisplayName("Decryption failure is wrapped in a RuntimeException naming the field")
    void decryptionFailureWrapsException() {
        assertThatThrownBy(() -> new FailingConverter().convertToEntityAttribute("v1:AAEC"))
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("boom");
        System.out.println("✓ Underlying failure wrapped in RuntimeException naming the field");
    }
}
