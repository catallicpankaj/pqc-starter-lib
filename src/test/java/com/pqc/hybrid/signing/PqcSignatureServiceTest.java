package com.pqc.hybrid.signing;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.*;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Security;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for {@link PqcSignatureService} — the Dilithium-3 sign/verify facade matching the
 * published blog's exact API shape: {@code sign(data, privateKey)},
 * {@code verify(data, signature, publicKey)}.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class PqcSignatureServiceTest {

    private static PqcSignatureService     pqcSig;
    private static DilithiumSigningEngine dilithium;

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BCPQC") == null) Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);
        dilithium = new DilithiumSigningEngine();
        pqcSig    = new PqcSignatureService(dilithium);
    }

    @Test @Order(1)
    @DisplayName("sign(data, privateKey) + verify(data, signature, publicKey) round-trips")
    void signVerifyRoundTrip() throws Exception {
        KeyPair keyPair = dilithium.generateKeyPair();
        byte[] document  = "LOAN AGREEMENT: Principal $250,000, 30yr fixed".getBytes(StandardCharsets.UTF_8);

        byte[] signature = pqcSig.sign(document, keyPair.getPrivate());
        boolean valid    = pqcSig.verify(document, signature, keyPair.getPublic());

        assertThat(valid).isTrue();
        assertThat(signature.length).isGreaterThan(3000); // Dilithium-3 signature, ~3300 bytes
        System.out.printf("✓ sign/verify round-trip: %d byte document -> %d byte signature -> valid%n",
            document.length, signature.length);
    }

    @Test @Order(2)
    @DisplayName("Tampered document is rejected — verify() returns false, does not throw")
    void tamperedDocumentRejected() throws Exception {
        KeyPair keyPair = dilithium.generateKeyPair();
        byte[] original  = "original terms".getBytes(StandardCharsets.UTF_8);
        byte[] tampered  = "altered terms!!".getBytes(StandardCharsets.UTF_8);

        byte[] signature = pqcSig.sign(original, keyPair.getPrivate());
        boolean valid    = pqcSig.verify(tampered, signature, keyPair.getPublic());

        assertThat(valid).isFalse();
        System.out.println("✓ Tampered document correctly rejected by verify()");
    }

    @Test @Order(3)
    @DisplayName("Wrong public key is rejected")
    void wrongPublicKeyRejected() throws Exception {
        KeyPair signerKeyPair = dilithium.generateKeyPair();
        KeyPair otherKeyPair  = dilithium.generateKeyPair();
        byte[] document = "audit record".getBytes(StandardCharsets.UTF_8);

        byte[] signature = pqcSig.sign(document, signerKeyPair.getPrivate());
        boolean valid    = pqcSig.verify(document, signature, otherKeyPair.getPublic());

        assertThat(valid).isFalse();
        System.out.println("✓ Wrong public key correctly rejected by verify()");
    }

    @Test @Order(4)
    @DisplayName("Same document signed twice with two different key pairs produces two verifiably distinct signatures")
    void signaturesAreKeySpecific() throws Exception {
        KeyPair signerA = dilithium.generateKeyPair();
        KeyPair signerB = dilithium.generateKeyPair();
        byte[] document = "shared document content".getBytes(StandardCharsets.UTF_8);

        byte[] sigA = pqcSig.sign(document, signerA.getPrivate());
        byte[] sigB = pqcSig.sign(document, signerB.getPrivate());

        assertThat(pqcSig.verify(document, sigA, signerA.getPublic())).isTrue();
        assertThat(pqcSig.verify(document, sigB, signerB.getPublic())).isTrue();
        assertThat(pqcSig.verify(document, sigA, signerB.getPublic())).isFalse();
        assertThat(pqcSig.verify(document, sigB, signerA.getPublic())).isFalse();
        System.out.println("✓ Signatures are key-specific — cross-verification correctly rejected");
    }

    @Test @Order(5)
    @DisplayName("Blog Use Case 4 shape: JWT-style signingInput sign/verify (service account token pattern)")
    void jwtStyleSigningInput() throws Exception {
        KeyPair authServerKeyPair = dilithium.generateKeyPair();
        String header  = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"alg\":\"DILITHIUM3\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"sub\":\"swift-connector\",\"scope\":\"read\"}".getBytes(StandardCharsets.UTF_8));
        String signingInput = header + "." + payload;

        byte[] signature = pqcSig.sign(signingInput.getBytes(StandardCharsets.UTF_8), authServerKeyPair.getPrivate());
        boolean valid = pqcSig.verify(
            signingInput.getBytes(StandardCharsets.UTF_8), signature, authServerKeyPair.getPublic());

        assertThat(valid).isTrue();
        System.out.println("✓ Blog Use Case 4 JWT signingInput pattern verified");
    }
}
