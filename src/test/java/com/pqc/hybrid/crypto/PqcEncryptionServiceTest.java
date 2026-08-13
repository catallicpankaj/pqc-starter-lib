package com.pqc.hybrid.crypto;

import tools.jackson.databind.ObjectMapper;
import com.pqc.hybrid.handshake.HybridHandshakeOrchestrator;
import com.pqc.hybrid.handshake.KyberKemEngine;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.*;

import javax.crypto.AEADBadTagException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Security;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for {@link PqcEncryptionService}'s public-key-addressed encrypt()/decrypt() methods —
 * the stateless API added to match the published blog's Use Cases 1 and 2. Unlike the
 * session-based flow (covered by {@code AesGcmEngineTest}), these tests never call
 * {@code establishHybridSession()} — the recipient's key pair is the only shared state.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class PqcEncryptionServiceTest {

    private static PqcEncryptionService pqc;
    private static KyberKemEngine       kyberEngine;

    @BeforeAll
    static void setup() throws Exception {
        if (Security.getProvider("BC")    == null) Security.insertProviderAt(new BouncyCastleProvider(),    1);
        if (Security.getProvider("BCPQC") == null) Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);

        kyberEngine = new KyberKemEngine();
        // The stateless encrypt()/decrypt() methods never touch the orchestrator — an ephemeral
        // one is only present here to satisfy the constructor.
        HybridHandshakeOrchestrator orchestrator = new HybridHandshakeOrchestrator(Optional.empty());
        pqc = new PqcEncryptionService(orchestrator, new AesGcmEngine(), kyberEngine);
    }

    @Test @Order(1)
    @DisplayName("encrypt(data, recipientPublicKey) -> decrypt(payload, privateKey) round-trips")
    void encryptDecryptRoundTrip() throws Exception {
        KeyPair recipient = kyberEngine.generateKeyPair();
        byte[] plaintext  = "customer payment instruction".getBytes(StandardCharsets.UTF_8);

        PqcEncryptedPayload encrypted = pqc.encrypt(plaintext, recipient.getPublic());
        byte[] decrypted = pqc.decrypt(encrypted, recipient.getPrivate());

        assertThat(decrypted).isEqualTo(plaintext);
        assertThat(encrypted.encapsulatedKey()).hasSize(1088); // Kyber-768 ciphertext, fixed size
        assertThat(encrypted.iv()).hasSize(12);
        System.out.printf("✓ encrypt/decrypt: %d bytes -> %d byte encapsulated key + %d byte ciphertext -> recovered%n",
            plaintext.length, encrypted.encapsulatedKey().length, encrypted.ciphertext().length);
    }

    @Test @Order(2)
    @DisplayName("encryptToBytes() -> decrypt(byte[], privateKey) round-trips via the serialized wire format")
    void encryptToBytesRoundTrip() throws Exception {
        KeyPair recipient = kyberEngine.generateKeyPair();
        byte[] plaintext  = "SSN: 123-45-6789".getBytes(StandardCharsets.UTF_8);

        byte[] wire = pqc.encryptToBytes(plaintext, recipient.getPublic());
        byte[] decrypted = pqc.decrypt(wire, recipient.getPrivate());

        assertThat(decrypted).isEqualTo(plaintext);
        System.out.printf("✓ encryptToBytes/decrypt(byte[]): %d bytes -> %d wire bytes -> recovered%n",
            plaintext.length, wire.length);
    }

    @Test @Order(3)
    @DisplayName("PqcEncryptedPayload.toBytes() matches what decrypt(byte[]) expects — explicit wire format check")
    void toBytesMatchesDecryptByteArrayFormat() throws Exception {
        KeyPair recipient = kyberEngine.generateKeyPair();
        byte[] plaintext  = "explicit wire format check".getBytes(StandardCharsets.UTF_8);

        PqcEncryptedPayload encrypted = pqc.encrypt(plaintext, recipient.getPublic());
        byte[] wire = encrypted.toBytes();

        assertThat(wire.length).isEqualTo(
            encrypted.encapsulatedKey().length + encrypted.iv().length + encrypted.ciphertext().length);

        byte[] decrypted = pqc.decrypt(wire, recipient.getPrivate());
        assertThat(decrypted).isEqualTo(plaintext);
        System.out.println("✓ PqcEncryptedPayload.toBytes() is exactly what decrypt(byte[]) parses back");
    }

    @Test @Order(4)
    @DisplayName("Tampered ciphertext is rejected (GCM authentication)")
    void tamperedCiphertextRejected() throws Exception {
        KeyPair recipient = kyberEngine.generateKeyPair();
        PqcEncryptedPayload encrypted = pqc.encrypt("sensitive".getBytes(StandardCharsets.UTF_8), recipient.getPublic());

        byte[] tamperedCt = encrypted.ciphertext().clone();
        tamperedCt[tamperedCt.length / 2] ^= 0xFF;
        PqcEncryptedPayload tampered = new PqcEncryptedPayload(encrypted.encapsulatedKey(), encrypted.iv(), tamperedCt);

        assertThatThrownBy(() -> pqc.decrypt(tampered, recipient.getPrivate()))
            .isInstanceOf(AEADBadTagException.class);
        System.out.println("✓ Tampered ciphertext rejected by GCM authentication tag");
    }

    @Test @Order(5)
    @DisplayName("Tampered encapsulated key is rejected (wrong shared secret recovered -> GCM fails)")
    void tamperedEncapsulatedKeyRejected() throws Exception {
        KeyPair recipient = kyberEngine.generateKeyPair();
        PqcEncryptedPayload encrypted = pqc.encrypt("sensitive".getBytes(StandardCharsets.UTF_8), recipient.getPublic());

        byte[] tamperedKey = encrypted.encapsulatedKey().clone();
        tamperedKey[0] ^= 0xFF;
        PqcEncryptedPayload tampered = new PqcEncryptedPayload(tamperedKey, encrypted.iv(), encrypted.ciphertext());

        assertThatThrownBy(() -> pqc.decrypt(tampered, recipient.getPrivate()))
            .isInstanceOf(Exception.class); // Kyber decapsulate + wrong AES key -> AEADBadTagException
        System.out.println("✓ Tampered encapsulated key rejected — wrong shared secret fails GCM tag check");
    }

    @Test @Order(6)
    @DisplayName("Wrong private key cannot decrypt")
    void wrongPrivateKeyRejected() throws Exception {
        KeyPair recipient = kyberEngine.generateKeyPair();
        KeyPair wrongKey   = kyberEngine.generateKeyPair();
        PqcEncryptedPayload encrypted = pqc.encrypt("sensitive".getBytes(StandardCharsets.UTF_8), recipient.getPublic());

        assertThatThrownBy(() -> pqc.decrypt(encrypted, wrongKey.getPrivate()))
            .isInstanceOf(Exception.class);
        System.out.println("✓ Wrong private key rejected — cannot decrypt data encrypted to a different recipient");
    }

    @Test @Order(7)
    @DisplayName("Different recipients: same plaintext encrypts differently, only the matching key decrypts")
    void differentRecipientsAreIsolated() throws Exception {
        KeyPair recipientA = kyberEngine.generateKeyPair();
        KeyPair recipientB = kyberEngine.generateKeyPair();
        byte[] plaintext = "shared plaintext".getBytes(StandardCharsets.UTF_8);

        PqcEncryptedPayload forA = pqc.encrypt(plaintext, recipientA.getPublic());
        PqcEncryptedPayload forB = pqc.encrypt(plaintext, recipientB.getPublic());

        assertThat(forA).isNotEqualTo(forB); // different encapsulation each time
        assertThat(pqc.decrypt(forA, recipientA.getPrivate())).isEqualTo(plaintext);
        assertThat(pqc.decrypt(forB, recipientB.getPrivate())).isEqualTo(plaintext);
        assertThatThrownBy(() -> pqc.decrypt(forA, recipientB.getPrivate())).isInstanceOf(Exception.class);
        System.out.println("✓ Different recipients: isolated ciphertexts, cross-decryption rejected");
    }

    @Test @Order(8)
    @DisplayName("PqcEncryptedPayload serializes/deserializes as JSON via Jackson (usable as @RequestBody)")
    void jacksonJsonRoundTrip() throws Exception {
        KeyPair recipient = kyberEngine.generateKeyPair();
        PqcEncryptedPayload encrypted = pqc.encrypt("REST payload".getBytes(StandardCharsets.UTF_8), recipient.getPublic());

        ObjectMapper mapper = new ObjectMapper();
        String json = mapper.writeValueAsString(encrypted);
        PqcEncryptedPayload restored = mapper.readValue(json, PqcEncryptedPayload.class);

        assertThat(restored).isEqualTo(encrypted);
        byte[] decrypted = pqc.decrypt(restored, recipient.getPrivate());
        assertThat(decrypted).isEqualTo("REST payload".getBytes(StandardCharsets.UTF_8));
        System.out.println("✓ PqcEncryptedPayload JSON round-trip via Jackson ObjectMapper — usable as @RequestBody");
    }

    @Test @Order(9)
    @DisplayName("Blog Use Case 1: Transaction Service encrypts to Core Banking's public key, no session involved")
    void blogUseCase1TransactionServiceToCoreBankingService() throws Exception {
        // Core Banking Service generates its own long-lived Kyber key pair (out of band, e.g. via
        // PqcKeyPairGenerator or KMS) and publishes only the public key.
        KeyPair coreBankingKeyPair = kyberEngine.generateKeyPair();

        // Two INDEPENDENT PqcEncryptionService instances — simulating two separate microservices.
        // They share nothing except Core Banking's public key; there is no live session between them.
        PqcEncryptionService transactionServicePqc =
            new PqcEncryptionService(new HybridHandshakeOrchestrator(Optional.empty()), new AesGcmEngine(), new KyberKemEngine());
        PqcEncryptionService coreBankingServicePqc =
            new PqcEncryptionService(new HybridHandshakeOrchestrator(Optional.empty()), new AesGcmEngine(), new KyberKemEngine());

        // Transaction Service: sender
        byte[] paymentInstruction = "{\"amount\":9999.99,\"currency\":\"USD\"}".getBytes(StandardCharsets.UTF_8);
        PqcEncryptedPayload encrypted = transactionServicePqc.encrypt(paymentInstruction, coreBankingKeyPair.getPublic());

        // ...serialized over HTTP as JSON, deserialized on the other side...
        ObjectMapper mapper = new ObjectMapper();
        PqcEncryptedPayload received = mapper.readValue(mapper.writeValueAsBytes(encrypted), PqcEncryptedPayload.class);

        // Core Banking Service: receiver — decrypts with its own private key
        byte[] decrypted = coreBankingServicePqc.decrypt(received, coreBankingKeyPair.getPrivate());

        assertThat(decrypted).isEqualTo(paymentInstruction);
        System.out.println("✓ Blog Use Case 1 pattern verified: two independent services, no shared session, "
            + "public-key-addressed encryption end to end");
    }
}
