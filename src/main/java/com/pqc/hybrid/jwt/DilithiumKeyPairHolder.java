package com.pqc.hybrid.jwt;

import com.pqc.hybrid.keymanagement.service.QuantumKeyService;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.util.Optional;

/**
 * Manages the Dilithium-3 signing keypair used by {@link DilithiumJwtService}.
 *
 * Follows the same Optional-injection pattern as {@link com.pqc.hybrid.handshake.HybridHandshakeOrchestrator}:
 *
 *   Phase 3 present  →  keypair loaded from KMS via QuantumKeyService
 *                        (persists across restarts, rotates on schedule)
 *
 *   Phase 3 absent   →  ephemeral in-memory keypair generated at startup
 *                        (new key on every restart, suitable for dev/test)
 *
 * This class is constructed by PqcAutoConfiguration and injected into DilithiumJwtService.
 */
public class DilithiumKeyPairHolder {

    private static final Logger log = LoggerFactory.getLogger(DilithiumKeyPairHolder.class);
    private static final String BCPQC = "BCPQC";

    // Phase 3 present: read fresh from QuantumKeyService on every use, so a scheduled/manual
    // rotation (KeyRotationManager) takes effect on the next token issued — nothing here is
    // cached across a rotation. Phase 3 absent: a single ephemeral key pair, generated once
    // (there is nowhere to rotate it to without a KMS).
    private final Optional<QuantumKeyService> quantumKeyService;
    private final KeyPair                     ephemeralKeyPair;

    static {
        if (Security.getProvider(BCPQC) == null) {
            Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);
        }
    }

    /**
     * @param quantumKeyService  Present when Phase 3 is configured — uses the KMS-managed key.
     *                           Empty for Phase 1/2 backwards compatibility — uses an ephemeral key.
     */
    public DilithiumKeyPairHolder(Optional<QuantumKeyService> quantumKeyService) throws Exception {
        this.quantumKeyService = quantumKeyService;
        if (quantumKeyService.isPresent()) {
            this.ephemeralKeyPair = null;
            log.info("DilithiumKeyPairHolder using KMS-managed Dilithium-3 key — provider={}",
                quantumKeyService.get().getProviderName());
        } else {
            this.ephemeralKeyPair = generateEphemeralKeyPair();
            log.info("DilithiumKeyPairHolder using ephemeral Dilithium-3 key (Phase 3 not configured)");
        }
    }

    /** Returns the Dilithium-3 private key for signing JWT tokens. */
    public PrivateKey getPrivateKey() {
        return currentKeyPair().getPrivate();
    }

    /** Returns the Dilithium-3 public key for verifying JWT tokens. */
    public PublicKey getPublicKey() {
        return currentKeyPair().getPublic();
    }

    private KeyPair currentKeyPair() {
        return quantumKeyService.isPresent()
            ? quantumKeyService.get().getActiveDilithiumKeyPair()
            : ephemeralKeyPair;
    }

    /**
     * Returns where this key came from — either {@code "kms:<providerName>"}
     * or {@code "ephemeral"}. Useful for actuator/monitoring.
     */
    public String getSource() {
        return quantumKeyService.isPresent()
            ? "kms:" + quantumKeyService.get().getProviderName()
            : "ephemeral";
    }

    private static KeyPair generateEphemeralKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium", BCPQC);
        kpg.initialize(DilithiumParameterSpec.dilithium3);
        KeyPair kp = kpg.generateKeyPair();
        log.debug("Generated ephemeral Dilithium-3 keypair: pubKey={}B", kp.getPublic().getEncoded().length);
        return kp;
    }
}
