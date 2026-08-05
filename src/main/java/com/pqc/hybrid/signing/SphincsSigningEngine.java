package com.pqc.hybrid.signing;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.*;

/**
 * Real SPHINCS+-SHA2-128f Digital Signature engine.
 *
 * SPHINCS+ is a stateless hash-based signature scheme — its security relies
 * ONLY on the security of the underlying hash function (SHA-2/SHAKE),
 * making it the most conservative choice among NIST PQC standards.
 *
 * Key sizes (SPHINCS+-SHA2-128f):
 *   Public key:  32 bytes  ← tiny
 *   Private key: 64 bytes  ← tiny
 *   Signature:   17088 bytes ← large (tradeoff for hash-based security)
 *
 * Best used for: long-term signing keys, code signing, certificate authorities.
 * Avoid for: high-frequency signing (signature size is large).
 *
 * Compare with Dilithium-3:
 *   Dilithium: faster signing, lattice-based, 3293-byte signatures
 *   SPHINCS+:  slower signing, hash-based (more conservative), 17088-byte signatures
 */
@Component
public class SphincsSigningEngine {

    private static final Logger log = LoggerFactory.getLogger(SphincsSigningEngine.class);
    private static final String BCPQC = "BCPQC";

    static {
        if (Security.getProvider(BCPQC) == null) {
            Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);
        }
    }

    /**
     * Generate a SPHINCS+-SHA2-128f key pair.
     * Note: key generation is slower than Dilithium (~200ms vs ~5ms).
     */
    public KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", BCPQC);
        kpg.initialize(SPHINCSPlusParameterSpec.sha2_128f);
        KeyPair kp = kpg.generateKeyPair();
        log.debug("SPHINCS+-SHA2-128f key pair: pubKey={} bytes, privKey={} bytes",
            kp.getPublic().getEncoded().length,
            kp.getPrivate().getEncoded().length);
        return kp;
    }

    /**
     * Sign data with SPHINCS+.
     * Note: signing is slower than Dilithium and produces large signatures (~17KB).
     * Best for low-frequency, high-security scenarios.
     */
    public byte[] sign(PrivateKey privateKey, byte[] data) throws Exception {
        Signature signer = Signature.getInstance("SPHINCSPlus", BCPQC);
        signer.initSign(privateKey);
        signer.update(data);
        byte[] signature = signer.sign();
        log.debug("SPHINCS+ signed {} bytes → signature {} bytes", data.length, signature.length);
        return signature;
    }

    /**
     * Verify a SPHINCS+ signature.
     */
    public boolean verify(PublicKey publicKey, byte[] data, byte[] signature) throws Exception {
        Signature verifier = Signature.getInstance("SPHINCSPlus", BCPQC);
        verifier.initVerify(publicKey);
        verifier.update(data);
        boolean valid = verifier.verify(signature);
        log.debug("SPHINCS+ verify: {}", valid ? "VALID" : "INVALID");
        return valid;
    }

    public byte[] signString(PrivateKey privateKey, String payload) throws Exception {
        return sign(privateKey, payload.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    public boolean verifyString(PublicKey publicKey, String payload, byte[] signature) throws Exception {
        return verify(publicKey, payload.getBytes(java.nio.charset.StandardCharsets.UTF_8), signature);
    }
}
