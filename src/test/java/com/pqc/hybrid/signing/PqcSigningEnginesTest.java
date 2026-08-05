package com.pqc.hybrid.signing;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.*;

import java.security.KeyPair;
import java.security.Security;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for real Dilithium-3 and SPHINCS+-SHA2-128f signing.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class PqcSigningEnginesTest {

    private static DilithiumSigningEngine dilithium;
    private static SphincsSigningEngine   sphincs;

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BC")    == null) Security.insertProviderAt(new BouncyCastleProvider(),    1);
        if (Security.getProvider("BCPQC") == null) Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);
        dilithium = new DilithiumSigningEngine();
        sphincs   = new SphincsSigningEngine();
    }

    // ── Dilithium-3 Tests ─────────────────────────────────────────────

    @Test
    @Order(1)
    @DisplayName("Dilithium-3: key pair has expected sizes")
    void dilithiumKeyPairSizes() throws Exception {
        KeyPair kp = dilithium.generateKeyPair();
        System.out.printf("Dilithium-3 public key:  %d bytes%n", kp.getPublic().getEncoded().length);
        System.out.printf("Dilithium-3 private key: %d bytes%n", kp.getPrivate().getEncoded().length);

        assertThat(kp.getPublic().getEncoded().length).isGreaterThan(1800);
        assertThat(kp.getPrivate().getEncoded().length).isGreaterThan(3500);
    }

    @Test
    @Order(2)
    @DisplayName("Dilithium-3: sign and verify round-trip")
    void dilithiumSignVerify() throws Exception {
        KeyPair kp      = dilithium.generateKeyPair();
        byte[] message  = "Spring Boot PQC integration test".getBytes();
        byte[] sig      = dilithium.sign(kp.getPrivate(), message);

        assertThat(sig).isNotNull();
        assertThat(sig.length).isGreaterThan(3000);

        boolean valid = dilithium.verify(kp.getPublic(), message, sig);
        assertThat(valid).isTrue();

        System.out.printf("Dilithium-3 signature: %d bytes ✓%n", sig.length);
    }

    @Test
    @Order(3)
    @DisplayName("Dilithium-3: tampered message fails verification")
    void dilithiumTamperedMessageFails() throws Exception {
        KeyPair kp       = dilithium.generateKeyPair();
        byte[] message   = "original message".getBytes();
        byte[] tampered  = "tampered message".getBytes();
        byte[] sig       = dilithium.sign(kp.getPrivate(), message);

        boolean valid    = dilithium.verify(kp.getPublic(), tampered, sig);
        assertThat(valid).isFalse();
        System.out.println("Tampered message correctly rejected ✓");
    }

    @Test
    @Order(4)
    @DisplayName("Dilithium-3: wrong public key fails verification")
    void dilithiumWrongKeyFails() throws Exception {
        KeyPair kp1     = dilithium.generateKeyPair();
        KeyPair kp2     = dilithium.generateKeyPair();
        byte[] message  = "test".getBytes();
        byte[] sig      = dilithium.sign(kp1.getPrivate(), message);

        boolean valid   = dilithium.verify(kp2.getPublic(), message, sig);
        assertThat(valid).isFalse();
        System.out.println("Wrong public key correctly rejected ✓");
    }

    @Test
    @Order(5)
    @DisplayName("Dilithium-3: string convenience methods work")
    void dilithiumStringMethods() throws Exception {
        KeyPair kp     = dilithium.generateKeyPair();
        String payload = "{\"sub\":\"user123\",\"role\":\"admin\"}";
        byte[] sig     = dilithium.signString(kp.getPrivate(), payload);
        boolean valid  = dilithium.verifyString(kp.getPublic(), payload, sig);

        assertThat(valid).isTrue();
        System.out.println("Dilithium-3 JWT payload signing ✓");
    }

    @Test
    @Order(6)
    @DisplayName("Dilithium-3: performance benchmark (10 sign+verify)")
    void dilithiumPerformance() throws Exception {
        KeyPair kp     = dilithium.generateKeyPair();
        byte[] message = "benchmark payload".getBytes();
        int runs       = 10;
        long total     = 0;

        for (int i = 0; i < runs; i++) {
            long t    = System.nanoTime();
            byte[] sig = dilithium.sign(kp.getPrivate(), message);
            dilithium.verify(kp.getPublic(), message, sig);
            total    += System.nanoTime() - t;
        }

        double avgMs = total / runs / 1_000_000.0;
        System.out.printf("Dilithium-3 sign+verify avg: %.3f ms%n", avgMs);
        assertThat(avgMs).isLessThan(1000);
    }

    // ── SPHINCS+ Tests ────────────────────────────────────────────────

    @Test
    @Order(7)
    @DisplayName("SPHINCS+: key pair has tiny public key (hash-based property)")
    void sphincsKeyPairSizes() throws Exception {
        KeyPair kp = sphincs.generateKeyPair();
        System.out.printf("SPHINCS+ public key:  %d bytes%n", kp.getPublic().getEncoded().length);
        System.out.printf("SPHINCS+ private key: %d bytes%n", kp.getPrivate().getEncoded().length);

        // SPHINCS+ has very small keys — big advantage over lattice-based schemes
        assertThat(kp.getPublic().getEncoded().length).isLessThan(200);
    }

    @Test
    @Order(8)
    @DisplayName("SPHINCS+: sign and verify round-trip")
    void sphincsSignVerify() throws Exception {
        KeyPair kp     = sphincs.generateKeyPair();
        byte[] message = "Long-term certificate signing with SPHINCS+".getBytes();
        byte[] sig     = sphincs.sign(kp.getPrivate(), message);

        assertThat(sig).isNotNull();
        assertThat(sig.length).isGreaterThan(10000); // large signatures are expected

        boolean valid  = sphincs.verify(kp.getPublic(), message, sig);
        assertThat(valid).isTrue();

        System.out.printf("SPHINCS+ signature: %d bytes ✓%n", sig.length);
    }

    @Test
    @Order(9)
    @DisplayName("SPHINCS+: tampered message fails verification")
    void sphincsTamperedFails() throws Exception {
        KeyPair kp      = sphincs.generateKeyPair();
        byte[] sig      = sphincs.sign(kp.getPrivate(), "original".getBytes());
        boolean valid   = sphincs.verify(kp.getPublic(), "tampered".getBytes(), sig);
        assertThat(valid).isFalse();
        System.out.println("SPHINCS+ tampered message correctly rejected ✓");
    }

    // ── Comparison ────────────────────────────────────────────────────

    @Test
    @Order(10)
    @DisplayName("Algorithm comparison: Dilithium vs SPHINCS+")
    void algorithmComparison() throws Exception {
        byte[] message = "comparison test".getBytes();

        // Dilithium
        KeyPair dKP  = dilithium.generateKeyPair();
        long dStart  = System.nanoTime();
        byte[] dSig  = dilithium.sign(dKP.getPrivate(), message);
        long dMs     = (System.nanoTime() - dStart) / 1_000_000;

        // SPHINCS+
        KeyPair sKP  = sphincs.generateKeyPair();
        long sStart  = System.nanoTime();
        byte[] sSig  = sphincs.sign(sKP.getPrivate(), message);
        long sMs     = (System.nanoTime() - sStart) / 1_000_000;

        System.out.println("\n─── Algorithm Comparison ──────────────────────────");
        System.out.printf("  %-25s sig=%5d bytes  sign=%3d ms  pubkey=%4d bytes%n",
            "Dilithium-3 (ML-DSA-65)", dSig.length, dMs, dKP.getPublic().getEncoded().length);
        System.out.printf("  %-25s sig=%5d bytes  sign=%3d ms  pubkey=%4d bytes%n",
            "SPHINCS+-SHA2-128f", sSig.length, sMs, sKP.getPublic().getEncoded().length);
        System.out.println("────────────────────────────────────────────────────");
        System.out.println("  Use Dilithium for: frequent signing (APIs, JWTs)");
        System.out.println("  Use SPHINCS+ for:  long-term keys (CAs, certificates)");
    }
}
