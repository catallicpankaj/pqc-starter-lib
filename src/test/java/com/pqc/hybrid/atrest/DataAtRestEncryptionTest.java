package com.pqc.hybrid.atrest;

import com.pqc.hybrid.atrest.config.AtRestEncryptionAutoConfiguration;
import com.pqc.hybrid.atrest.config.AtRestEncryptionProperties;
import com.pqc.hybrid.crypto.AesGcmEngine;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.security.Security;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for Phase 6 — Data at Rest encryption.
 *
 * All tests run without a Spring context — direct unit tests of:
 *   - HkdfKeyDerivation        (key derivation properties)
 *   - EncryptedFieldService    (field encrypt/decrypt, versioned format)
 *   - StreamingAesGcmEngine    (chunked streaming AES-256-GCM)
 *   - ReEncryptionService      (lazy re-encryption after key rotation)
 *   - AtRestEncryptionService  (top-level API)
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class DataAtRestEncryptionTest {

    private static final byte[] MASTER_KEY_V1 = new byte[32];
    private static final byte[] MASTER_KEY_V2 = new byte[32];

    private static HkdfKeyDerivation       hkdf;
    private static EncryptedFieldService   fieldServiceV1;
    private static EncryptedFieldService   fieldServiceV2;
    private static StreamingAesGcmEngine   streamEngine;
    private static ReEncryptionService     reEncService;
    private static AtRestEncryptionService atRestService;

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BC") == null)
            Security.insertProviderAt(new BouncyCastleProvider(), 1);

        // Deterministic keys for reproducible tests
        for (int i = 0; i < 32; i++) {
            MASTER_KEY_V1[i] = (byte) (i + 1);   // 0x01..0x20
            MASTER_KEY_V2[i] = (byte) (i + 33);  // 0x21..0x40
        }

        hkdf           = new HkdfKeyDerivation();
        fieldServiceV1 = new EncryptedFieldService(new AesGcmEngine(), hkdf, MASTER_KEY_V1, 1);
        fieldServiceV2 = new EncryptedFieldService(new AesGcmEngine(), hkdf, MASTER_KEY_V2, 2);
        streamEngine   = new StreamingAesGcmEngine();
        // dual-key: previousService=V1 (for decryption), currentService=V2 (for re-encryption)
        reEncService   = new ReEncryptionService(fieldServiceV1, fieldServiceV2);
        atRestService  = new AtRestEncryptionService(fieldServiceV1, streamEngine,
                                                      new ReEncryptionService(fieldServiceV1));
    }

    // ── HKDF Key Derivation ──────────────────────────────────────────────────

    @Test @Order(1)
    @DisplayName("HKDF derives a 32-byte key from master key + recordId + fieldName")
    void hkdfDerivesSizedKey() {
        byte[] derived = hkdf.deriveFieldKey(MASTER_KEY_V1, "patient-42", "ssn", 1);
        assertThat(derived).hasSize(32);
        System.out.println("✓ HKDF: derived 32-byte key");
    }

    @Test @Order(2)
    @DisplayName("HKDF produces different keys for different field names (key isolation)")
    void hkdfFieldIsolation() {
        byte[] ssnKey  = hkdf.deriveFieldKey(MASTER_KEY_V1, "patient-42", "ssn",           1);
        byte[] diagKey = hkdf.deriveFieldKey(MASTER_KEY_V1, "patient-42", "diagnosisCode",  1);
        assertThat(ssnKey).isNotEqualTo(diagKey);
        System.out.println("✓ HKDF: ssn and diagnosisCode derive different keys");
    }

    @Test @Order(3)
    @DisplayName("HKDF produces different keys for different record IDs (row isolation)")
    void hkdfRowIsolation() {
        byte[] key42 = hkdf.deriveFieldKey(MASTER_KEY_V1, "patient-42", "ssn", 1);
        byte[] key99 = hkdf.deriveFieldKey(MASTER_KEY_V1, "patient-99", "ssn", 1);
        assertThat(key42).isNotEqualTo(key99);
        System.out.println("✓ HKDF: patient-42 and patient-99 derive different keys");
    }

    // ── EncryptedFieldService ────────────────────────────────────────────────

    @Test @Order(4)
    @DisplayName("Field encrypt/decrypt round-trip recovers plaintext")
    void fieldEncryptDecryptRoundTrip() throws Exception {
        String plaintext = "123-45-6789";
        String encoded   = fieldServiceV1.encryptField(plaintext, "patient-42", "ssn");
        String recovered = fieldServiceV1.decryptField(encoded,   "patient-42", "ssn");

        assertThat(recovered).isEqualTo(plaintext);
        assertThat(encoded).startsWith("v1:");
        System.out.printf("✓ Field round-trip: \"%s\" → encoded(%d chars) → \"%s\"%n",
                plaintext, encoded.length(), recovered);
    }

    @Test @Order(5)
    @DisplayName("Two encryptions of the same value produce different ciphertext (IV randomness)")
    void fieldEncryptionIsRandomised() throws Exception {
        String encoded1 = fieldServiceV1.encryptField("secret", "rec-1", "field");
        String encoded2 = fieldServiceV1.encryptField("secret", "rec-1", "field");
        assertThat(encoded1).isNotEqualTo(encoded2);
        System.out.println("✓ Field encryption: same plaintext → different ciphertext (random IV)");
    }

    @Test @Order(6)
    @DisplayName("needsReEncryption returns true when stored version < current master version")
    void needsReEncryptionDetectsOldVersion() throws Exception {
        // Encrypted under V1
        String encodedV1 = fieldServiceV1.encryptField("data", "rec-1", "col");

        // fieldServiceV2 has version 2 — should flag V1 value as needing re-encryption
        assertThat(fieldServiceV2.needsReEncryption(encodedV1)).isTrue();
        // fieldServiceV1 has version 1 — should not flag its own output
        assertThat(fieldServiceV1.needsReEncryption(encodedV1)).isFalse();
        System.out.println("✓ needsReEncryption: v1 value flagged by v2 service, not by v1 service");
    }

    // ── StreamingAesGcmEngine ────────────────────────────────────────────────

    @Test @Order(7)
    @DisplayName("Streaming encrypt/decrypt round-trip recovers plaintext for small payload")
    void streamingRoundTripSmall() throws Exception {
        byte[] key       = randomKey();
        byte[] plaintext = "Hello, PqcStarterLib streaming!".getBytes();

        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        streamEngine.encryptStream(key, new ByteArrayInputStream(plaintext), cipherOut);

        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        streamEngine.decryptStream(key, new ByteArrayInputStream(cipherOut.toByteArray()), plainOut);

        assertThat(plainOut.toByteArray()).isEqualTo(plaintext);
        System.out.printf("✓ Streaming round-trip: %d plaintext → %d encrypted → %d decrypted%n",
                plaintext.length, cipherOut.size(), plainOut.size());
    }

    @Test @Order(8)
    @DisplayName("Streaming encrypt/decrypt round-trip recovers plaintext for multi-chunk payload")
    void streamingRoundTripMultiChunk() throws Exception {
        // Use small chunk engine (32 bytes) to force multiple chunks
        StreamingAesGcmEngine smallChunk = new StreamingAesGcmEngine(32);
        byte[] key       = randomKey();
        byte[] plaintext = new byte[200];
        new SecureRandom().nextBytes(plaintext);

        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        smallChunk.encryptStream(key, new ByteArrayInputStream(plaintext), cipherOut);

        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        smallChunk.decryptStream(key, new ByteArrayInputStream(cipherOut.toByteArray()), plainOut);

        assertThat(plainOut.toByteArray()).isEqualTo(plaintext);
        System.out.printf("✓ Multi-chunk streaming: 200 bytes in 32-byte chunks, recovered correctly%n");
    }

    @Test @Order(9)
    @DisplayName("Streaming decryption fails with wrong key (GCM authentication)")
    void streamingWrongKeyFails() throws Exception {
        byte[] key1      = randomKey();
        byte[] key2      = randomKey();
        byte[] plaintext = "sensitive data".getBytes();

        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        streamEngine.encryptStream(key1, new ByteArrayInputStream(plaintext), cipherOut);

        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        assertThatThrownBy(() ->
            streamEngine.decryptStream(key2, new ByteArrayInputStream(cipherOut.toByteArray()), plainOut))
            .isInstanceOf(Exception.class);
        System.out.println("✓ Streaming: wrong key causes authentication failure (GCM tag mismatch)");
    }

    // ── ReEncryptionService ──────────────────────────────────────────────────

    @Test @Order(10)
    @DisplayName("reEncryptIfNeeded migrates v1 value to v2 without loss")
    void reEncryptIfNeededMigratesValue() throws Exception {
        String original  = "sensitive-payload";
        String encodedV1 = fieldServiceV1.encryptField(original, "rec-1", "col");
        assertThat(encodedV1).startsWith("v1:");

        String encodedV2 = reEncService.reEncryptIfNeeded(encodedV1, "rec-1", "col");
        assertThat(encodedV2).startsWith("v2:");

        // Verify round-trip with new key
        String recovered = fieldServiceV2.decryptField(encodedV2, "rec-1", "col");
        assertThat(recovered).isEqualTo(original);
        System.out.println("✓ reEncryptIfNeeded: v1→v2 migration, plaintext preserved");
    }

    @Test @Order(11)
    @DisplayName("reEncryptIfNeeded is a no-op when value is already at current version")
    void reEncryptIfNeededSkipsCurrentVersion() throws Exception {
        String encodedV1 = fieldServiceV1.encryptField("data", "rec-1", "col");

        // reEncService uses fieldServiceV2 (version 2), so v1 needs migration
        String encodedV2 = reEncService.reEncryptIfNeeded(encodedV1, "rec-1", "col");
        // Calling again on v2 should return the same value
        String encodedV2Again = reEncService.reEncryptIfNeeded(encodedV2, "rec-1", "col");
        assertThat(encodedV2Again).isEqualTo(encodedV2);
        System.out.println("✓ reEncryptIfNeeded: calling twice is idempotent (no-op on current version)");
    }

    // ── AtRestEncryptionService (top-level API) ──────────────────────────────

    @Test @Order(12)
    @DisplayName("AtRestEncryptionService encryptBytes/decryptBytes round-trip")
    void atRestBytesRoundTrip() throws Exception {
        byte[] key  = randomKey();
        byte[] data = "PqcStarterLib Phase 6".getBytes();

        byte[] encrypted = atRestService.encryptBytes(key, data);
        byte[] decrypted = atRestService.decryptBytes(key, encrypted);

        assertThat(decrypted).isEqualTo(data);
        assertThat(encrypted).isNotEqualTo(data);
        System.out.printf("✓ AtRestEncryptionService bytes: %d → %d → %d (round-trip OK)%n",
                data.length, encrypted.length, decrypted.length);
    }

    // ── AtRestEncryptionAutoConfiguration — master key rotation wiring ───────

    @Test @Order(13)
    @DisplayName("Rotation: previous-master-key-hex lets old data survive a genuine master key change")
    void autoConfigurationSupportsMasterKeyRotation() throws Exception {
        AtRestEncryptionAutoConfiguration autoConfig = new AtRestEncryptionAutoConfiguration();
        HkdfKeyDerivation hkdfLocal = new HkdfKeyDerivation();

        // Step 1: "before rotation" — only master-key-hex set (version 1)
        AtRestEncryptionProperties beforeProps = new AtRestEncryptionProperties();
        beforeProps.setMasterKeyHex(toHex(MASTER_KEY_V1));
        beforeProps.setMasterKeyVersion(1);

        EncryptedFieldService beforeService = autoConfig.encryptedFieldService(beforeProps, hkdfLocal);
        String storedUnderOldKey = beforeService.encryptField("123-45-6789", "patient-7", "ssn");
        assertThat(storedUnderOldKey).startsWith("v1:");

        // Step 2: "after rotation" — master-key-hex is now a DIFFERENT key (version 2),
        // previous-master-key-hex holds the OLD key so old data isn't stranded.
        AtRestEncryptionProperties afterProps = new AtRestEncryptionProperties();
        afterProps.setMasterKeyHex(toHex(MASTER_KEY_V2));
        afterProps.setMasterKeyVersion(2);
        afterProps.setPreviousMasterKeyHex(toHex(MASTER_KEY_V1));

        EncryptedFieldService afterService = autoConfig.encryptedFieldService(afterProps, hkdfLocal);
        ReEncryptionService rotatedReEncService =
                autoConfig.reEncryptionService(afterService, afterProps, hkdfLocal);

        // Without the fix, this decrypt fails (AEADBadTagException) because the auto-wired
        // ReEncryptionService would only know about the NEW key, not the OLD one.
        String reEncrypted = rotatedReEncService.reEncryptIfNeeded(storedUnderOldKey, "patient-7", "ssn");
        assertThat(reEncrypted).startsWith("v2:");

        String recovered = afterService.decryptField(reEncrypted, "patient-7", "ssn");
        assertThat(recovered).isEqualTo("123-45-6789");
        System.out.println("✓ AtRestEncryptionAutoConfiguration: rotation via previous-master-key-hex preserves data");
    }

    @Test @Order(14)
    @DisplayName("No rotation in progress: reEncryptionService() falls back to single-key behaviour")
    void autoConfigurationSingleKeyWhenNoPreviousKeyConfigured() {
        AtRestEncryptionAutoConfiguration autoConfig = new AtRestEncryptionAutoConfiguration();
        HkdfKeyDerivation hkdfLocal = new HkdfKeyDerivation();

        AtRestEncryptionProperties props = new AtRestEncryptionProperties();
        props.setMasterKeyHex(toHex(MASTER_KEY_V1));
        props.setMasterKeyVersion(1);
        // previousMasterKeyHex left blank — default, no rotation in progress

        EncryptedFieldService service = autoConfig.encryptedFieldService(props, hkdfLocal);
        ReEncryptionService reEnc = autoConfig.reEncryptionService(service, props, hkdfLocal);

        assertThat(reEnc.needsReEncryption("v1:AAEC")).isFalse();
        System.out.println("✓ AtRestEncryptionAutoConfiguration: single-key behaviour unchanged when no rotation configured");
    }

    // ── StreamingAesGcmEngine — attack resistance ─────────────────────────────

    @Test @Order(19)
    @DisplayName("Streaming: swapping two chunks is detected and rejected (AAD binds each chunk to its position)")
    void streamingChunkReorderRejected() throws Exception {
        StreamingAesGcmEngine smallChunk = new StreamingAesGcmEngine(16);
        byte[] key = randomKey();
        // 3 chunks of 16 bytes each, distinguishable content per chunk
        byte[] plaintext = "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC".substring(0, 48).getBytes();

        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        smallChunk.encryptStream(key, new ByteArrayInputStream(plaintext), cipherOut);
        byte[] wire = cipherOut.toByteArray();

        byte[] reordered = swapFirstTwoChunks(wire);

        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        assertThatThrownBy(() ->
            smallChunk.decryptStream(key, new ByteArrayInputStream(reordered), plainOut))
            .isInstanceOf(Exception.class); // AEADBadTagException — AAD (chunk index) no longer matches position
        System.out.println("✓ Streaming: reordered chunks rejected — chunk-index AAD prevents silent reordering");
    }

    @Test @Order(20)
    @DisplayName("Streaming: corrupted magic bytes are rejected before any decryption is attempted")
    void streamingCorruptedMagicRejected() throws Exception {
        byte[] key = randomKey();
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        streamEngine.encryptStream(key, new ByteArrayInputStream("hello".getBytes()), cipherOut);
        byte[] wire = cipherOut.toByteArray();
        wire[0] = 0x00; // corrupt the first magic byte ("PQCS" -> invalid)

        assertThatThrownBy(() ->
            streamEngine.decryptStream(key, new ByteArrayInputStream(wire), new ByteArrayOutputStream()))
            .isInstanceOf(java.io.IOException.class)
            .hasMessageContaining("magic");
        System.out.println("✓ Streaming: corrupted magic bytes rejected with a clear error, before decrypting anything");
    }

    @Test @Order(21)
    @DisplayName("Streaming: unsupported format version is rejected")
    void streamingUnsupportedVersionRejected() throws Exception {
        byte[] key = randomKey();
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        streamEngine.encryptStream(key, new ByteArrayInputStream("hello".getBytes()), cipherOut);
        byte[] wire = cipherOut.toByteArray();
        wire[4] = 0x02; // magic is 4 bytes (indices 0-3); version byte is index 4 — bump 0x01 -> 0x02

        assertThatThrownBy(() ->
            streamEngine.decryptStream(key, new ByteArrayInputStream(wire), new ByteArrayOutputStream()))
            .isInstanceOf(java.io.IOException.class)
            .hasMessageContaining("version");
        System.out.println("✓ Streaming: unsupported format version rejected");
    }

    // ── Helper ───────────────────────────────────────────────────────────────

    private static byte[] randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return key;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /**
     * Manually swaps the first two chunk records in a PQCS wire-format stream produced
     * by StreamingAesGcmEngine, leaving the 9-byte header (magic+version+chunkSize) and
     * any subsequent chunks/EOF marker untouched. Each chunk record is
     * [chunkLen:4B][chunkLen bytes of IV+ciphertext+tag].
     */
    private static byte[] swapFirstTwoChunks(byte[] wire) {
        int pos = 9; // header: 4 (magic) + 1 (version) + 4 (chunkSize)

        int len1 = readBigEndianInt(wire, pos);
        int start1 = pos, recordLen1 = 4 + len1;

        int pos2 = start1 + recordLen1;
        int len2 = readBigEndianInt(wire, pos2);
        int start2 = pos2, recordLen2 = 4 + len2;

        byte[] result = wire.clone();
        System.arraycopy(wire, start2, result, start1, recordLen2);
        System.arraycopy(wire, start1, result, start1 + recordLen2, recordLen1);
        return result;
    }

    private static int readBigEndianInt(byte[] b, int offset) {
        return ((b[offset] & 0xFF) << 24) | ((b[offset + 1] & 0xFF) << 16)
             | ((b[offset + 2] & 0xFF) << 8) | (b[offset + 3] & 0xFF);
    }
}
