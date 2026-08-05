package com.pqc.hybrid.keymanagement.service;

import com.pqc.hybrid.keymanagement.api.KeyManagementProvider;
import com.pqc.hybrid.keymanagement.api.KeyVersion;
import com.pqc.hybrid.keymanagement.api.WrappedKeyMaterial;
import com.pqc.hybrid.keymanagement.registry.KeyRegistry;
import jakarta.annotation.PostConstruct;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;

/**
 * ═══════════════════════════════════════════════════════════════════════
 * QUANTUM KEY SERVICE — Top-level Phase 3 entry point
 * ═══════════════════════════════════════════════════════════════════════
 *
 * Bridges the cryptographic key generation (BouncyCastle) with the key
 * protection and persistence layer (KeyManagementProvider).
 *
 * RESPONSIBILITIES:
 *   1. Bootstrap  — on startup, load existing keys from the provider OR
 *                   generate new ones, wrap them, and persist them.
 *   2. Provide    — supply the active Kyber and EC KeyPairs to
 *                   HybridHandshakeOrchestrator for use in handshakes.
 *   3. Rotate     — generate a new key version, deprecate the old one,
 *                   persist both changes via the provider.
 *
 * BOOTSTRAP FLOW (runs once in @PostConstruct):
 *
 *   For each managed key ("kyber-server-key", "ec-server-key"):
 *   ┌─────────────────────────────────────────────────────────┐
 *   │  List stored versions via provider                      │
 *   │     ├── None found (first startup):                     │
 *   │     │     1. Generate keypair with BouncyCastle         │
 *   │     │     2. Wrap private key via provider.wrapKey()    │
 *   │     │     3. Store KeyVersion via provider.store()      │
 *   │     │     4. Register in KeyRegistry                    │
 *   │     └── Found (restart):                                │
 *   │           1. Load latest ACTIVE version from provider   │
 *   │           2. Unwrap private key via provider.unwrapKey()│
 *   │           3. Reconstruct KeyPair from bytes             │
 *   │           4. Register in KeyRegistry                    │
 *   └─────────────────────────────────────────────────────────┘
 *
 * KEY IDs managed:
 *   KEY_KYBER      = "kyber-server-key"      — Kyber-768 keypair for KEM
 *   KEY_EC         = "ec-server-key"         — ECDHE-P384 keypair for classical component
 *   KEY_DILITHIUM  = "dilithium-signing-key" — Dilithium-3 keypair for JWT signing
 */
public class QuantumKeyService {

    private static final Logger log = LoggerFactory.getLogger(QuantumKeyService.class);

    public static final String KEY_KYBER     = "kyber-server-key";
    public static final String KEY_EC        = "ec-server-key";
    public static final String KEY_DILITHIUM = "dilithium-signing-key";

    private static final String BC    = "BC";
    private static final String BCPQC = "BCPQC";

    private final KeyManagementProvider provider;
    private final KeyRegistry           registry;

    // Cached active keypairs — populated during bootstrap(), updated during rotate()
    private volatile KeyPair activeKyberKeyPair;
    private volatile KeyPair activeEcKeyPair;
    private volatile KeyPair activeDilithiumKeyPair;

    static {
        if (Security.getProvider(BC)    == null) Security.insertProviderAt(new BouncyCastleProvider(),    1);
        if (Security.getProvider(BCPQC) == null) Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);
    }

    public QuantumKeyService(KeyManagementProvider provider, KeyRegistry registry) {
        this.provider = provider;
        this.registry = registry;
    }

    // ─────────────────────────────────────────────────────────────
    // Bootstrap — called by Spring on startup via @PostConstruct
    // ─────────────────────────────────────────────────────────────

    @PostConstruct
    public void bootstrap() throws Exception {
        log.info("QuantumKeyService bootstrap starting — provider={}", provider.providerName());

        if (!provider.isHealthy()) {
            throw new IllegalStateException(
                "KMS provider '" + provider.providerName() + "' is not reachable. " +
                "Check your pqc.key-management configuration.");
        }

        activeKyberKeyPair     = bootstrapKey(KEY_KYBER,     KeyVersion.KeyAlgorithm.KYBER_768);
        activeEcKeyPair        = bootstrapKey(KEY_EC,        KeyVersion.KeyAlgorithm.EC_P384);
        activeDilithiumKeyPair = bootstrapKey(KEY_DILITHIUM, KeyVersion.KeyAlgorithm.DILITHIUM_3);

        log.info("QuantumKeyService ready — Kyber pub={}B  EC pub={}B  Dilithium pub={}B  provider={}",
            activeKyberKeyPair.getPublic().getEncoded().length,
            activeEcKeyPair.getPublic().getEncoded().length,
            activeDilithiumKeyPair.getPublic().getEncoded().length,
            provider.providerName());
    }

    // ─────────────────────────────────────────────────────────────
    // Key access — called by HybridHandshakeOrchestrator
    // ─────────────────────────────────────────────────────────────

    /** Returns the active Kyber-768 keypair for use in KEM handshakes. */
    public KeyPair getActiveKyberKeyPair() {
        assertBootstrapped(activeKyberKeyPair, KEY_KYBER);
        return activeKyberKeyPair;
    }

    /** Returns the active ECDHE-P384 keypair for use in classical handshakes. */
    public KeyPair getActiveEcKeyPair() {
        assertBootstrapped(activeEcKeyPair, KEY_EC);
        return activeEcKeyPair;
    }

    /** Returns the active Dilithium-3 keypair for use in JWT signing. */
    public KeyPair getActiveDilithiumKeyPair() {
        assertBootstrapped(activeDilithiumKeyPair, KEY_DILITHIUM);
        return activeDilithiumKeyPair;
    }

    /** Returns the key registry for actuator / monitoring access. */
    public KeyRegistry getRegistry() { return registry; }

    /** Returns the active provider name for actuator reporting. */
    public String getProviderName() { return provider.providerName(); }

    /** Probes the underlying provider's connectivity/health — for actuator reporting. */
    public boolean isProviderHealthy() { return provider.isHealthy(); }

    // ─────────────────────────────────────────────────────────────
    // Key Rotation — called by KeyRotationManager on schedule
    // ─────────────────────────────────────────────────────────────

    /**
     * Rotates the key with the given ID:
     *   1. Generates a new keypair
     *   2. Wraps the new private key via the provider
     *   3. Stores the new version (ACTIVE)
     *   4. Deprecates the old version (DEPRECATED) and updates its stored state
     *   5. Updates the cached keypair
     *
     * The old key remains available for decryption (DEPRECATED status) until
     * explicitly retired by KeyRotationManager after the deprecation window.
     */
    public synchronized void rotate(String keyId) throws Exception {
        KeyVersion.KeyAlgorithm algo = switch (keyId) {
            case KEY_KYBER     -> KeyVersion.KeyAlgorithm.KYBER_768;
            case KEY_DILITHIUM -> KeyVersion.KeyAlgorithm.DILITHIUM_3;
            default            -> KeyVersion.KeyAlgorithm.EC_P384;
        };

        log.info("[rotation] starting rotation for keyId={} algo={}", keyId, algo.getLabel());

        // 1. Generate new keypair
        KeyPair newPair = generateKeyPair(algo);

        // 2. Wrap new private key
        int newVersion = registry.latestVersion(keyId) + 1;
        WrappedKeyMaterial wrappedNew = provider.wrapKey(keyId, newPair.getPrivate().getEncoded());
        WrappedKeyMaterial versionedWrapped = WrappedKeyMaterial.of(
            keyId, newVersion, wrappedNew.wrappedBytes(),
            wrappedNew.algorithm(), wrappedNew.providerName(), wrappedNew.context());

        // 3. Build and store new ACTIVE version
        KeyVersion newKv = KeyVersion.builder()
            .keyId(keyId)
            .version(newVersion)
            .algorithm(algo)
            .publicKey(newPair.getPublic())
            .wrappedPrivateKey(versionedWrapped)
            .status(KeyVersion.Status.ACTIVE)
            .build();
        provider.storeKeyVersion(newKv);
        registry.register(newKv);

        // 4. Deprecate the previous active version
        KeyVersion oldActive = registry.getActive(keyId);
        if (oldActive.getVersion() != newVersion) {
            oldActive.deprecate();
            provider.storeKeyVersion(oldActive); // persist the DEPRECATED status
            registry.register(oldActive);
            log.info("[rotation] deprecated old version: keyId={} version={}", keyId, oldActive.getVersion());
        }

        // 5. Update cached keypair
        switch (keyId) {
            case KEY_KYBER     -> activeKyberKeyPair     = newPair;
            case KEY_DILITHIUM -> activeDilithiumKeyPair = newPair;
            default            -> activeEcKeyPair        = newPair;
        }

        log.info("[rotation] completed: keyId={} newVersion={} provider={}",
            keyId, newVersion, provider.providerName());
    }

    /**
     * Retires all DEPRECATED versions of the given key that are older than
     * the deprecation window. Called by KeyRotationManager after the window expires.
     */
    public synchronized void retireDeprecated(String keyId) throws Exception {
        List<KeyVersion> deprecated = registry.getAll(keyId).stream()
            .filter(kv -> kv.getStatus() == KeyVersion.Status.DEPRECATED)
            .toList();

        for (KeyVersion kv : deprecated) {
            kv.retire();
            provider.storeKeyVersion(kv);
            registry.register(kv);
            log.info("[rotation] retired: keyId={} version={}", keyId, kv.getVersion());
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Internal helpers
    // ─────────────────────────────────────────────────────────────

    private KeyPair bootstrapKey(String keyId, KeyVersion.KeyAlgorithm algo) throws Exception {
        List<Integer> versions = provider.listKeyVersions(keyId);

        if (versions.isEmpty()) {
            return generateAndStore(keyId, algo, 1);
        }

        // Restart path: load latest active version
        int latestVersion = versions.get(versions.size() - 1);
        KeyVersion kv = provider.loadKeyVersion(keyId, latestVersion)
            .orElseThrow(() -> new IllegalStateException(
                "Version metadata listed but load returned empty for keyId=" + keyId));

        // Also load any deprecated versions (needed for decryption of old sessions)
        for (int v : versions) {
            if (v != latestVersion) {
                provider.loadKeyVersion(keyId, v).ifPresent(registry::register);
            }
        }

        registry.register(kv);
        byte[] rawPrivKey = provider.unwrapKey(keyId, kv.getWrappedPrivateKey());
        KeyPair pair = reconstructKeyPair(algo, kv.getPublicKey(), rawPrivKey);
        log.info("[bootstrap] loaded keyId={} version={} algo={}", keyId, latestVersion, algo.getLabel());
        return pair;
    }

    private KeyPair generateAndStore(String keyId, KeyVersion.KeyAlgorithm algo, int version) throws Exception {
        log.info("[bootstrap] first startup — generating {} keypair for keyId={}", algo.getLabel(), keyId);

        KeyPair pair = generateKeyPair(algo);
        WrappedKeyMaterial wrapped = provider.wrapKey(keyId, pair.getPrivate().getEncoded());
        WrappedKeyMaterial versioned = WrappedKeyMaterial.of(
            keyId, version, wrapped.wrappedBytes(),
            wrapped.algorithm(), wrapped.providerName(), wrapped.context());

        KeyVersion kv = KeyVersion.builder()
            .keyId(keyId)
            .version(version)
            .algorithm(algo)
            .publicKey(pair.getPublic())
            .wrappedPrivateKey(versioned)
            .status(KeyVersion.Status.ACTIVE)
            .build();

        provider.storeKeyVersion(kv);
        registry.register(kv);
        log.info("[bootstrap] generated and stored: keyId={} version={} algo={}", keyId, version, algo.getLabel());
        return pair;
    }

    private KeyPair generateKeyPair(KeyVersion.KeyAlgorithm algo) throws Exception {
        return switch (algo) {
            case KYBER_768 -> {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", BCPQC);
                kpg.initialize(KyberParameterSpec.kyber768);
                yield kpg.generateKeyPair();
            }
            case EC_P384 -> {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BC);
                kpg.initialize(new ECGenParameterSpec("secp384r1"));
                yield kpg.generateKeyPair();
            }
            case DILITHIUM_3 -> {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium", BCPQC);
                kpg.initialize(DilithiumParameterSpec.dilithium3);
                yield kpg.generateKeyPair();
            }
        };
    }

    private KeyPair reconstructKeyPair(KeyVersion.KeyAlgorithm algo,
                                       PublicKey publicKey, byte[] rawPrivKey) throws Exception {
        KeyFactory kf = KeyFactory.getInstance(algo.getBcAlgorithmName(), algo.getBcProviderName());
        PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(rawPrivKey));
        return new KeyPair(publicKey, privateKey);
    }

    private void assertBootstrapped(KeyPair pair, String keyId) {
        if (pair == null) {
            throw new IllegalStateException(
                "KeyPair for " + keyId + " is not initialised. " +
                "QuantumKeyService.bootstrap() may not have completed.");
        }
    }
}
