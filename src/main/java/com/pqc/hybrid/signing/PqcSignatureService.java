package com.pqc.hybrid.signing;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Top-level signing/verification facade over {@link DilithiumSigningEngine} — the quantum-safe
 * replacement for RSA/ECDSA signing. Use this for anything that must remain provably unaltered for
 * years: loan agreements, KYC documents, audit records, build artifacts, and long-lived OAuth2
 * service tokens.
 *
 * Dilithium-3 only — for hash-based signing with a more conservative security assumption (at the
 * cost of much larger signatures), use {@link SphincsSigningEngine} directly.
 *
 * USAGE:
 *
 *   @Autowired PqcSignatureService pqcSig;
 *
 *   byte[] signature = pqcSig.sign(document, myPrivateKey);
 *   boolean valid     = pqcSig.verify(document, signature, myPublicKey);
 *
 * Note the parameter order: {@code (data, ..., key)} throughout — {@link DilithiumSigningEngine}'s
 * own methods take the key first; this facade reorders internally to keep {@code data} as the
 * leading argument in both {@code sign()} and {@code verify()}.
 */
@Service
public class PqcSignatureService {

    private static final Logger log = LoggerFactory.getLogger(PqcSignatureService.class);

    private final DilithiumSigningEngine dilithium;

    public PqcSignatureService(DilithiumSigningEngine dilithium) {
        this.dilithium = dilithium;
    }

    /**
     * Sign data with Dilithium-3.
     *
     * @param data       the content to sign — a document, a build artifact digest, a JWT signing
     *                   input, anything that needs to prove it has not been altered
     * @param privateKey Dilithium-3 private key
     * @return           Dilithium-3 signature (~3300 bytes)
     */
    public byte[] sign(byte[] data, PrivateKey privateKey) throws Exception {
        byte[] signature = dilithium.sign(privateKey, data);
        log.debug("Signed {} bytes → {} byte signature", data.length, signature.length);
        return signature;
    }

    /**
     * Verify a Dilithium-3 signature.
     *
     * @param data       the original data that was signed
     * @param signature  the signature to verify
     * @param publicKey  Dilithium-3 public key matching the signer's private key
     * @return           true if the signature is valid and the data has not been altered
     */
    public boolean verify(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
        boolean valid = dilithium.verify(publicKey, data, signature);
        log.debug("Verify {} bytes against {} byte signature: {}", data.length, signature.length, valid);
        return valid;
    }
}
