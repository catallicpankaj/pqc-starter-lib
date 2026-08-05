package com.pqc.hybrid.signing;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.*;

/**
 * Real Dilithium-3 (ML-DSA-65) Digital Signature engine.
 *
 * Uses BouncyCastle BCPQC provider — genuine Dilithium-3, not simulated.
 * Suitable for replacing RSA/ECDSA in JWT signing, message authentication,
 * code signing, and any scenario requiring quantum-safe digital signatures.
 *
 * Key sizes (Dilithium-3):
 *   Public key:  1952 bytes
 *   Private key: 4000 bytes
 *   Signature:   3293 bytes
 *
 * Usage:
 *   DilithiumSigningEngine engine = new DilithiumSigningEngine();
 *   KeyPair kp  = engine.generateKeyPair();
 *   byte[] sig  = engine.sign(kp.getPrivate(), message);
 *   boolean ok  = engine.verify(kp.getPublic(), message, sig);
 */
@Component
public class DilithiumSigningEngine {

    private static final Logger log = LoggerFactory.getLogger(DilithiumSigningEngine.class);
    private static final String BCPQC = "BCPQC";

    static {
        if (Security.getProvider(BCPQC) == null) {
            Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);
        }
    }

    /**
     * Generate a Dilithium-3 key pair.
     * Store the private key securely (HSM or encrypted KeyStore in production).
     */
    public KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium", BCPQC);
        kpg.initialize(DilithiumParameterSpec.dilithium3);
        KeyPair kp = kpg.generateKeyPair();
        log.debug("Dilithium-3 key pair generated: pubKey={} bytes, privKey={} bytes",
            kp.getPublic().getEncoded().length,
            kp.getPrivate().getEncoded().length);
        return kp;
    }

    /**
     * Sign arbitrary byte data with Dilithium-3.
     *
     * @param privateKey  Dilithium-3 private key
     * @param data        Data to sign (e.g. JWT payload bytes, message bytes)
     * @return            Dilithium-3 signature (~3293 bytes)
     */
    public byte[] sign(PrivateKey privateKey, byte[] data) throws Exception {
        Signature signer = Signature.getInstance("Dilithium", BCPQC);
        signer.initSign(privateKey);
        signer.update(data);
        byte[] signature = signer.sign();
        log.debug("Dilithium-3 signed {} bytes → signature {} bytes", data.length, signature.length);
        return signature;
    }

    /**
     * Verify a Dilithium-3 signature.
     *
     * @param publicKey   Dilithium-3 public key
     * @param data        Original data that was signed
     * @param signature   Signature to verify
     * @return            true if signature is valid
     */
    public boolean verify(PublicKey publicKey, byte[] data, byte[] signature) throws Exception {
        Signature verifier = Signature.getInstance("Dilithium", BCPQC);
        verifier.initVerify(publicKey);
        verifier.update(data);
        boolean valid = verifier.verify(signature);
        log.debug("Dilithium-3 verify: {}", valid ? "VALID" : "INVALID");
        return valid;
    }

    /**
     * Sign a string payload (convenience method for JWT-like use cases).
     */
    public byte[] signString(PrivateKey privateKey, String payload) throws Exception {
        return sign(privateKey, payload.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /**
     * Verify a string payload signature.
     */
    public boolean verifyString(PublicKey publicKey, String payload, byte[] signature) throws Exception {
        return verify(publicKey, payload.getBytes(java.nio.charset.StandardCharsets.UTF_8), signature);
    }
}
