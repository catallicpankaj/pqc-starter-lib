package com.pqc.hybrid.crypto;

import com.pqc.hybrid.handshake.HybridHandshakeOrchestrator;
import com.pqc.hybrid.handshake.KyberKemEngine;
import com.pqc.hybrid.signing.DilithiumSigningEngine;
import com.pqc.hybrid.signing.PqcSignatureService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.*;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Security;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for {@link PqcKeyPairGenerator} — confirms it produces valid, distinct, usable key pairs
 * for both algorithms, and that those keys work end-to-end through the services that consume them
 * ({@link PqcEncryptionService}, {@link PqcSignatureService}).
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class PqcKeyPairGeneratorTest {

    private static PqcKeyPairGenerator keyGen;

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BC")    == null) Security.insertProviderAt(new BouncyCastleProvider(),    1);
        if (Security.getProvider("BCPQC") == null) Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);
        keyGen = new PqcKeyPairGenerator(new KyberKemEngine(), new DilithiumSigningEngine());
    }

    @Test @Order(1)
    @DisplayName("generateKyberKeyPair() produces a correctly-sized Kyber-768 key pair")
    void generatesKyberKeyPair() throws Exception {
        KeyPair pair = keyGen.generateKyberKeyPair();

        assertThat(pair.getPublic()).isNotNull();
        assertThat(pair.getPrivate()).isNotNull();
        assertThat(pair.getPublic().getEncoded().length).isGreaterThan(1000); // ~1208B encoded
        System.out.printf("✓ generateKyberKeyPair(): pubKey=%dB%n", pair.getPublic().getEncoded().length);
    }

    @Test @Order(2)
    @DisplayName("generateDilithiumKeyPair() produces a correctly-sized Dilithium-3 key pair")
    void generatesDilithiumKeyPair() throws Exception {
        KeyPair pair = keyGen.generateDilithiumKeyPair();

        assertThat(pair.getPublic()).isNotNull();
        assertThat(pair.getPrivate()).isNotNull();
        assertThat(pair.getPublic().getEncoded().length).isGreaterThan(1800); // ~1976B encoded
        System.out.printf("✓ generateDilithiumKeyPair(): pubKey=%dB%n", pair.getPublic().getEncoded().length);
    }

    @Test @Order(3)
    @DisplayName("Repeated calls produce distinct key pairs — nothing is cached")
    void repeatedCallsProduceDistinctKeys() throws Exception {
        KeyPair kyber1 = keyGen.generateKyberKeyPair();
        KeyPair kyber2 = keyGen.generateKyberKeyPair();
        KeyPair dilithium1 = keyGen.generateDilithiumKeyPair();
        KeyPair dilithium2 = keyGen.generateDilithiumKeyPair();

        assertThat(kyber1.getPublic().getEncoded()).isNotEqualTo(kyber2.getPublic().getEncoded());
        assertThat(dilithium1.getPublic().getEncoded()).isNotEqualTo(dilithium2.getPublic().getEncoded());
        System.out.println("✓ Repeated calls produce fresh, distinct key pairs");
    }

    @Test @Order(4)
    @DisplayName("Generated Kyber key pair works end-to-end through PqcEncryptionService")
    void kyberKeyPairUsableForEncryption() throws Exception {
        KeyPair recipient = keyGen.generateKyberKeyPair();
        PqcEncryptionService pqc = new PqcEncryptionService(
            new HybridHandshakeOrchestrator(Optional.empty()), new AesGcmEngine(), new KyberKemEngine());

        byte[] plaintext = "generated key works".getBytes(StandardCharsets.UTF_8);
        PqcEncryptedPayload encrypted = pqc.encrypt(plaintext, recipient.getPublic());
        byte[] decrypted = pqc.decrypt(encrypted, recipient.getPrivate());

        assertThat(decrypted).isEqualTo(plaintext);
        System.out.println("✓ Kyber key pair from PqcKeyPairGenerator works with PqcEncryptionService");
    }

    @Test @Order(5)
    @DisplayName("Generated Dilithium key pair works end-to-end through PqcSignatureService")
    void dilithiumKeyPairUsableForSigning() throws Exception {
        KeyPair signer = keyGen.generateDilithiumKeyPair();
        PqcSignatureService pqcSig = new PqcSignatureService(new DilithiumSigningEngine());

        byte[] document = "generated key signs documents".getBytes(StandardCharsets.UTF_8);
        byte[] signature = pqcSig.sign(document, signer.getPrivate());
        boolean valid = pqcSig.verify(document, signature, signer.getPublic());

        assertThat(valid).isTrue();
        System.out.println("✓ Dilithium key pair from PqcKeyPairGenerator works with PqcSignatureService");
    }
}
