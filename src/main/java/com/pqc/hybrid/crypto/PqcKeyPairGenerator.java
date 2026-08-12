package com.pqc.hybrid.crypto;

import java.security.KeyPair;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.pqc.hybrid.handshake.KyberKemEngine;
import com.pqc.hybrid.signing.DilithiumSigningEngine;

/**
 * Generates Kyber-768 and Dilithium-3 key pairs — a thin, autoconfigured facade over
 * {@link KyberKemEngine#generateKeyPair()} and {@link DilithiumSigningEngine#generateKeyPair()}.
 *
 * Every call generates a fresh, independent key pair — nothing is cached or persisted here. For
 * keys that need to survive a restart or be centrally managed, see the KMS-backed
 * {@code QuantumKeyService} (Phase 3) instead, which wraps generation together with storage,
 * versioning, and rotation.
 *
 * USAGE:
 *
 *   @Autowired PqcKeyPairGenerator keyGen;
 *
 *   KeyPair kyberKeys     = keyGen.generateKyberKeyPair();     // for PqcEncryptionService.encrypt()
 *   KeyPair dilithiumKeys = keyGen.generateDilithiumKeyPair(); // for PqcSignatureService.sign()
 */
@Component
public class PqcKeyPairGenerator {

    private static final Logger log = LoggerFactory.getLogger(PqcKeyPairGenerator.class);

    private final KyberKemEngine         kyber;
    private final DilithiumSigningEngine dilithium;

    public PqcKeyPairGenerator(KyberKemEngine kyber, DilithiumSigningEngine dilithium) {
        this.kyber     = kyber;
        this.dilithium = dilithium;
    }

    /** Generates a fresh Kyber-768 key pair, for use with {@link PqcEncryptionService}. */
    public KeyPair generateKyberKeyPair() throws Exception {
        KeyPair pair = kyber.generateKeyPair();
        log.debug("Generated Kyber-768 key pair: pubKey={}B", pair.getPublic().getEncoded().length);
        return pair;
    }

    /**
     * Generates a fresh Dilithium-3 key pair, for use with
     * {@link com.pqc.hybrid.signing.PqcSignatureService}.
     */
    public KeyPair generateDilithiumKeyPair() throws Exception {
        KeyPair pair = dilithium.generateKeyPair();
        log.debug("Generated Dilithium-3 key pair: pubKey={}B", pair.getPublic().getEncoded().length);
        return pair;
    }
}
