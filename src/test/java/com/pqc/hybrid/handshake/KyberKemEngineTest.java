package com.pqc.hybrid.handshake;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.*;

import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for real Kyber-768 KEM operations.
 * Verifies encapsulation/decapsulation produces matching shared secrets.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class KyberKemEngineTest {

    private static KyberKemEngine engine;

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BCPQC") == null)
            Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);
        engine = new KyberKemEngine();
    }

    @Test
    @Order(1)
    @DisplayName("Kyber-768 key pair has correct sizes")
    void keyPairSizes() throws Exception {
        KeyPair kp = engine.generateKeyPair();

        // Kyber-768 spec: public=1184 bytes, private=2400 bytes (encoded may differ slightly)
        assertThat(kp.getPublic().getEncoded().length).isGreaterThan(1000);
        assertThat(kp.getPrivate().getEncoded().length).isGreaterThan(2000);

        System.out.printf("Kyber-768 public key:  %d bytes%n", kp.getPublic().getEncoded().length);
        System.out.printf("Kyber-768 private key: %d bytes%n", kp.getPrivate().getEncoded().length);
    }

    @Test
    @Order(2)
    @DisplayName("Encapsulate + Decapsulate produces matching shared secret")
    void encapsulateDecapsulateRoundTrip() throws Exception {
        KeyPair serverKP = engine.generateKeyPair();

        // Client encapsulates to server's public key
        KyberKemEngine.KemResult kem = engine.encapsulate(serverKP.getPublic());

        // Server decapsulates with its private key
        byte[] serverSecret = engine.decapsulate(serverKP.getPrivate(), kem.ciphertext());

        // Both sides must derive the same shared secret
        assertThat(kem.sharedSecret()).isNotNull().hasSize(32);
        assertThat(serverSecret).isNotNull().hasSize(32);
        assertThat(kem.sharedSecret()).isEqualTo(serverSecret);

        System.out.printf("Shared secret: %d bytes ✓%n", kem.sharedSecret().length);
        System.out.printf("Ciphertext:    %d bytes%n",    kem.ciphertext().length);
    }

    @Test
    @Order(3)
    @DisplayName("Each encapsulation produces unique shared secret and ciphertext")
    void eachEncapsulationIsUnique() throws Exception {
        KeyPair serverKP = engine.generateKeyPair();

        KyberKemEngine.KemResult kem1 = engine.encapsulate(serverKP.getPublic());
        KyberKemEngine.KemResult kem2 = engine.encapsulate(serverKP.getPublic());

        assertThat(kem1.sharedSecret()).isNotEqualTo(kem2.sharedSecret());
        assertThat(kem1.ciphertext()).isNotEqualTo(kem2.ciphertext());
        System.out.println("Each encapsulation is unique ✓");
    }

    @Test
    @Order(4)
    @DisplayName("Wrong private key cannot decapsulate — produces different secret")
    void wrongPrivateKeyFails() throws Exception {
        KeyPair serverKP  = engine.generateKeyPair();
        KeyPair wrongKP   = engine.generateKeyPair(); // different key pair

        KyberKemEngine.KemResult kem = engine.encapsulate(serverKP.getPublic());

        // Decapsulating with wrong key — Kyber returns a random-looking value (IND-CCA2)
        byte[] wrongSecret = engine.decapsulate(wrongKP.getPrivate(), kem.ciphertext());
        assertThat(wrongSecret).isNotEqualTo(kem.sharedSecret());
        System.out.println("Wrong private key produces different secret ✓ (IND-CCA2 secure)");
    }

    @Test
    @Order(5)
    @DisplayName("Performance: 20 Kyber-768 KEM operations")
    void performance() throws Exception {
        KeyPair serverKP = engine.generateKeyPair();
        int runs = 20;
        long total = 0;

        for (int i = 0; i < runs; i++) {
            long t = System.nanoTime();
            KyberKemEngine.KemResult kem = engine.encapsulate(serverKP.getPublic());
            engine.decapsulate(serverKP.getPrivate(), kem.ciphertext());
            total += System.nanoTime() - t;
        }

        double avgMs = total / runs / 1_000_000.0;
        System.out.printf("Kyber-768 KEM avg (encap+decap): %.3f ms%n", avgMs);
        assertThat(avgMs).isLessThan(500); // should complete well under 500ms
    }

    // ── KemResult equals()/hashCode() — record with byte[] fields ───────────

    @Test
    @Order(6)
    @DisplayName("KemResult: two instances with identical content are equal (content, not reference)")
    void kemResultContentEquality() {
        byte[] secret1 = {1, 2, 3};
        byte[] secret2 = {1, 2, 3}; // same content, different array instance
        byte[] ct1 = {4, 5, 6};
        byte[] ct2 = {4, 5, 6};

        KyberKemEngine.KemResult a = new KyberKemEngine.KemResult(secret1, ct1);
        KyberKemEngine.KemResult b = new KyberKemEngine.KemResult(secret2, ct2);

        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
        System.out.println("✓ KemResult: content-based equals/hashCode, not reference-based");
    }

    @Test
    @Order(7)
    @DisplayName("KemResult: differing sharedSecret content makes instances unequal")
    void kemResultContentInequality() {
        KyberKemEngine.KemResult a = new KyberKemEngine.KemResult(new byte[]{1, 2, 3}, new byte[]{9, 9, 9});
        KyberKemEngine.KemResult b = new KyberKemEngine.KemResult(new byte[]{4, 5, 6}, new byte[]{9, 9, 9});

        assertThat(a).isNotEqualTo(b);
        System.out.println("✓ KemResult: different sharedSecret content -> not equal");
    }
}
