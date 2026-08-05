package com.pqc.hybrid.keymanagement;

import com.pqc.hybrid.actuator.PqcActuatorEndpoint;
import com.pqc.hybrid.jwt.DilithiumKeyPairHolder;
import com.pqc.hybrid.keymanagement.api.KeyVersion;
import com.pqc.hybrid.keymanagement.api.WrappedKeyMaterial;
import com.pqc.hybrid.keymanagement.config.KeyManagementProperties;
import com.pqc.hybrid.keymanagement.providers.LocalDevKeyProvider;
import com.pqc.hybrid.keymanagement.registry.KeyRegistry;
import com.pqc.hybrid.keymanagement.rotation.KeyRotationManager;
import com.pqc.hybrid.keymanagement.service.QuantumKeyService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.*;

import java.security.KeyPair;
import java.security.Security;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for Phase 3 Key Management.
 *
 * Uses LocalDevKeyProvider (no external dependencies required).
 * The same test scenarios apply to all providers — the Strategy interface
 * guarantees identical behaviour regardless of which provider is active.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class KeyManagementProviderTest {

    private static LocalDevKeyProvider   provider;
    private static KeyManagementProperties.Local localConfig;
    private static String tempKeyStorePath;

    @BeforeAll
    static void setup() throws Exception {
        if (Security.getProvider("BC")    == null) Security.insertProviderAt(new BouncyCastleProvider(),    1);
        if (Security.getProvider("BCPQC") == null) Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);

        // Use a temp directory for test key storage
        tempKeyStorePath = System.getProperty("java.io.tmpdir") +
                           "/pqc-starter-lib-test-" + System.currentTimeMillis() + "/local-master.key";

        localConfig = new KeyManagementProperties.Local();
        localConfig.setKeyStorePath(tempKeyStorePath);
        localConfig.setAutoGenerate(true);

        provider = new LocalDevKeyProvider(localConfig);
    }

    // ── LocalDevKeyProvider — Wrap / Unwrap ───────────────────────────────

    @Test @Order(1)
    @DisplayName("LocalDev: wrap/unwrap round-trip preserves raw key bytes")
    void wrapUnwrapRoundTrip() throws Exception {
        byte[] rawKey = new byte[32];
        new java.security.SecureRandom().nextBytes(rawKey);

        WrappedKeyMaterial wrapped = provider.wrapKey("test-key", rawKey);
        byte[] recovered = provider.unwrapKey("test-key", wrapped);

        assertThat(recovered).isEqualTo(rawKey);
        assertThat(wrapped.wrappedBytes()).isNotEqualTo(rawKey); // must be encrypted
        assertThat(wrapped.providerName()).isEqualTo("local");
        assertThat(wrapped.algorithm()).isEqualTo("AES/GCM/NoPadding");
        System.out.printf("✓ wrap/unwrap: %d raw bytes → %d wrapped bytes%n",
            rawKey.length, wrapped.wrappedBytes().length);
    }

    @Test @Order(2)
    @DisplayName("LocalDev: tampered wrapped bytes cannot be unwrapped")
    void tamperedWrappedBytesRejected() throws Exception {
        byte[] rawKey = new byte[32];
        new java.security.SecureRandom().nextBytes(rawKey);

        WrappedKeyMaterial wrapped = provider.wrapKey("tamper-test", rawKey);
        byte[] tampered = wrapped.wrappedBytes().clone();
        tampered[tampered.length / 2] ^= 0xFF;

        WrappedKeyMaterial tamperedMaterial = WrappedKeyMaterial.of(
            "tamper-test", wrapped.version(), tampered,
            wrapped.algorithm(), wrapped.providerName(), wrapped.context());

        assertThatThrownBy(() -> provider.unwrapKey("tamper-test", tamperedMaterial))
            .isInstanceOf(Exception.class);
        System.out.println("✓ tampered wrapped bytes correctly rejected by AES-GCM tag");
    }

    @Test @Order(3)
    @DisplayName("LocalDev: wrong keyId cannot unwrap (AAD mismatch)")
    void wrongKeyIdRejected() throws Exception {
        byte[] rawKey = new byte[32];
        new java.security.SecureRandom().nextBytes(rawKey);

        WrappedKeyMaterial wrapped = provider.wrapKey("key-A", rawKey);

        assertThatThrownBy(() -> provider.unwrapKey("key-B", wrapped))
            .isInstanceOf(Exception.class);
        System.out.println("✓ wrong keyId rejected — AAD binds ciphertext to keyId");
    }

    @Test @Order(4)
    @DisplayName("LocalDev: health check passes when master key is accessible")
    void healthCheckPasses() {
        assertThat(provider.isHealthy()).isTrue();
        System.out.println("✓ isHealthy() = true for LocalDevKeyProvider");
    }

    @Test @Order(5)
    @DisplayName("LocalDev: provider name matches configuration constant")
    void providerNameIsCorrect() {
        assertThat(provider.providerName()).isEqualTo("local");
    }

    // ── KeyRegistry ───────────────────────────────────────────────────────

    @Test @Order(6)
    @DisplayName("KeyRegistry: register and retrieve active version")
    void registryActiveVersion() throws Exception {
        KeyRegistry registry = new KeyRegistry();

        // Build a dummy KeyVersion (using a real EC key for simplicity)
        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(new java.security.spec.ECGenParameterSpec("secp384r1"));
        java.security.KeyPair pair = kpg.generateKeyPair();

        WrappedKeyMaterial wrapped = provider.wrapKey("ec-test", pair.getPrivate().getEncoded());
        KeyVersion kv = KeyVersion.builder()
            .keyId("ec-test").version(1)
            .algorithm(KeyVersion.KeyAlgorithm.EC_P384)
            .publicKey(pair.getPublic())
            .wrappedPrivateKey(wrapped)
            .status(KeyVersion.Status.ACTIVE)
            .build();

        registry.register(kv);

        assertThat(registry.getActive("ec-test")).isEqualTo(kv);
        assertThat(registry.latestVersion("ec-test")).isEqualTo(1);
        System.out.println("✓ KeyRegistry: stored and retrieved ACTIVE version");
    }

    @Test @Order(7)
    @DisplayName("KeyRegistry: deprecated version still usable for decryption, not encryption")
    void registryDeprecatedVersion() throws Exception {
        KeyRegistry registry = new KeyRegistry();

        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(new java.security.spec.ECGenParameterSpec("secp384r1"));
        java.security.KeyPair pair1 = kpg.generateKeyPair();
        java.security.KeyPair pair2 = kpg.generateKeyPair();

        WrappedKeyMaterial w1 = provider.wrapKey("rotate-test", pair1.getPrivate().getEncoded());
        WrappedKeyMaterial w2 = provider.wrapKey("rotate-test", pair2.getPrivate().getEncoded());

        KeyVersion v1 = KeyVersion.builder().keyId("rotate-test").version(1)
            .algorithm(KeyVersion.KeyAlgorithm.EC_P384).publicKey(pair1.getPublic())
            .wrappedPrivateKey(w1).status(KeyVersion.Status.ACTIVE).build();
        KeyVersion v2 = KeyVersion.builder().keyId("rotate-test").version(2)
            .algorithm(KeyVersion.KeyAlgorithm.EC_P384).publicKey(pair2.getPublic())
            .wrappedPrivateKey(w2).status(KeyVersion.Status.ACTIVE).build();

        registry.register(v1);
        v1.deprecate();
        registry.register(v1); // update status
        registry.register(v2); // new active

        assertThat(registry.getActive("rotate-test")).isEqualTo(v2);
        assertThat(registry.getUsableForDecryption("rotate-test")).hasSize(2); // V1 + V2
        assertThat(v1.isUsableForDecryption()).isTrue();
        assertThat(v1.isUsableForEncryption()).isFalse();
        System.out.println("✓ KeyRegistry: V1 DEPRECATED still usable for decryption, not encryption");
    }

    // ── QuantumKeyService — Bootstrap ────────────────────────────────────

    @Test @Order(8)
    @DisplayName("QuantumKeyService: bootstrap generates Kyber and EC keypairs on first startup")
    void quantumKeyServiceBootstrap() throws Exception {
        // Use a fresh temp path so this is always a "first startup"
        String freshPath = System.getProperty("java.io.tmpdir") +
                           "/qks-bootstrap-test-" + System.currentTimeMillis() + "/local-master.key";
        KeyManagementProperties.Local cfg = new KeyManagementProperties.Local();
        cfg.setKeyStorePath(freshPath);
        cfg.setAutoGenerate(true);

        LocalDevKeyProvider freshProvider = new LocalDevKeyProvider(cfg);
        KeyRegistry freshRegistry = new KeyRegistry();
        QuantumKeyService keyService = new QuantumKeyService(freshProvider, freshRegistry);
        keyService.bootstrap();

        KeyPair kyberPair = keyService.getActiveKyberKeyPair();
        KeyPair ecPair    = keyService.getActiveEcKeyPair();

        assertThat(kyberPair).isNotNull();
        assertThat(ecPair).isNotNull();
        assertThat(kyberPair.getPublic().getEncoded().length).isEqualTo(1208); // Kyber-768 X.509-encoded pubkey size
        assertThat(kyberPair.getPrivate()).isNotNull();
        assertThat(ecPair.getPublic().getAlgorithm()).isEqualTo("EC");

        System.out.printf("✓ Bootstrap: Kyber pubkey=%dB  EC pubkey=%dB%n",
            kyberPair.getPublic().getEncoded().length,
            ecPair.getPublic().getEncoded().length);
    }

    @Test @Order(9)
    @DisplayName("QuantumKeyService: restart loads same keypair (persistence round-trip)")
    void quantumKeyServicePersistenceRoundTrip() throws Exception {
        String sharedPath = System.getProperty("java.io.tmpdir") +
                            "/qks-restart-test-" + System.currentTimeMillis() + "/local-master.key";
        KeyManagementProperties.Local cfg = new KeyManagementProperties.Local();
        cfg.setKeyStorePath(sharedPath);
        cfg.setAutoGenerate(true);

        // First startup — generates and persists keys
        LocalDevKeyProvider p1 = new LocalDevKeyProvider(cfg);
        QuantumKeyService ks1 = new QuantumKeyService(p1, new KeyRegistry());
        ks1.bootstrap();
        byte[] originalKyberPubKey = ks1.getActiveKyberKeyPair().getPublic().getEncoded();

        // Second startup — loads the same keys from disk
        LocalDevKeyProvider p2 = new LocalDevKeyProvider(cfg);
        QuantumKeyService ks2 = new QuantumKeyService(p2, new KeyRegistry());
        ks2.bootstrap();
        byte[] reloadedKyberPubKey = ks2.getActiveKyberKeyPair().getPublic().getEncoded();

        assertThat(reloadedKyberPubKey).isEqualTo(originalKyberPubKey);
        System.out.println("✓ Persistence: same Kyber public key loaded after simulated restart");
    }

    @Test @Order(10)
    @DisplayName("QuantumKeyService: works with HybridHandshakeOrchestrator via Optional injection")
    void orchestratorUsesKmsKeys() throws Exception {
        String path = System.getProperty("java.io.tmpdir") +
                      "/qks-orchestrator-test-" + System.currentTimeMillis() + "/local-master.key";
        KeyManagementProperties.Local cfg = new KeyManagementProperties.Local();
        cfg.setKeyStorePath(path);
        cfg.setAutoGenerate(true);

        LocalDevKeyProvider p = new LocalDevKeyProvider(cfg);
        QuantumKeyService ks  = new QuantumKeyService(p, new KeyRegistry());
        ks.bootstrap();

        // Create orchestrator with Phase 3 keys
        com.pqc.hybrid.handshake.HybridHandshakeOrchestrator orchestrator =
            new com.pqc.hybrid.handshake.HybridHandshakeOrchestrator(Optional.of(ks));

        // The orchestrator's public key must match the KMS-managed key
        assertThat(orchestrator.getServerKyberPublicKey().getEncoded())
            .isEqualTo(ks.getActiveKyberKeyPair().getPublic().getEncoded());

        System.out.println("✓ Orchestrator uses KMS-managed Kyber key when QuantumKeyService is present");
    }

    @Test @Order(11)
    @DisplayName("QuantumKeyService: falls back to ephemeral keys when Optional is empty (Phase 1/2 compat)")
    void orchestratorFallsBackToEphemeralKeys() throws Exception {
        // No QuantumKeyService → ephemeral keys (existing Phase 1/2 behaviour)
        com.pqc.hybrid.handshake.HybridHandshakeOrchestrator orchestrator =
            new com.pqc.hybrid.handshake.HybridHandshakeOrchestrator(Optional.empty());

        assertThat(orchestrator.getServerKyberPublicKey()).isNotNull();
        assertThat(orchestrator.getServerEcPublicKey()).isNotNull();
        System.out.println("✓ Orchestrator falls back to ephemeral keys when Phase 3 is not configured");
    }

    // ── Key rotation takes effect on already-constructed beans ──────────────

    @Test @Order(12)
    @DisplayName("Rotation: HybridHandshakeOrchestrator reflects a rotated Kyber key without reconstruction")
    void orchestratorReflectsRotatedKyberKey() throws Exception {
        String path = System.getProperty("java.io.tmpdir") +
                      "/qks-rotation-orchestrator-test-" + System.currentTimeMillis() + "/local-master.key";
        KeyManagementProperties.Local cfg = new KeyManagementProperties.Local();
        cfg.setKeyStorePath(path);
        cfg.setAutoGenerate(true);

        QuantumKeyService ks = new QuantumKeyService(new LocalDevKeyProvider(cfg), new KeyRegistry());
        ks.bootstrap();

        com.pqc.hybrid.handshake.HybridHandshakeOrchestrator orchestrator =
            new com.pqc.hybrid.handshake.HybridHandshakeOrchestrator(Optional.of(ks));

        byte[] beforeRotation = orchestrator.getServerKyberPublicKey().getEncoded();

        ks.rotate(QuantumKeyService.KEY_KYBER);
        byte[] afterRotation = orchestrator.getServerKyberPublicKey().getEncoded();

        assertThat(afterRotation).isNotEqualTo(beforeRotation);
        assertThat(afterRotation).isEqualTo(ks.getActiveKyberKeyPair().getPublic().getEncoded());
        System.out.println("✓ Orchestrator picks up rotated Kyber key on next call — no restart required");
    }

    @Test @Order(13)
    @DisplayName("Rotation: DilithiumKeyPairHolder reflects a rotated Dilithium key without reconstruction")
    void keyHolderReflectsRotatedDilithiumKey() throws Exception {
        String path = System.getProperty("java.io.tmpdir") +
                      "/qks-rotation-dilithium-test-" + System.currentTimeMillis() + "/local-master.key";
        KeyManagementProperties.Local cfg = new KeyManagementProperties.Local();
        cfg.setKeyStorePath(path);
        cfg.setAutoGenerate(true);

        QuantumKeyService ks = new QuantumKeyService(new LocalDevKeyProvider(cfg), new KeyRegistry());
        ks.bootstrap();

        DilithiumKeyPairHolder holder = new DilithiumKeyPairHolder(Optional.of(ks));
        byte[] beforeRotation = holder.getPublicKey().getEncoded();

        ks.rotate(QuantumKeyService.KEY_DILITHIUM);
        byte[] afterRotation = holder.getPublicKey().getEncoded();

        assertThat(afterRotation).isNotEqualTo(beforeRotation);
        assertThat(afterRotation).isEqualTo(ks.getActiveDilithiumKeyPair().getPublic().getEncoded());
        System.out.println("✓ DilithiumKeyPairHolder picks up rotated key on next call — JWTs sign with the new key immediately");
    }

    @Test @Order(15)
    @DisplayName("Rotation: KeyRotationManager.triggerRotationNow() rotates Kyber, EC, AND Dilithium")
    void rotationManagerRotatesAllThreeManagedKeys() throws Exception {
        String path = System.getProperty("java.io.tmpdir") +
                      "/qks-rotation-manager-test-" + System.currentTimeMillis() + "/local-master.key";
        KeyManagementProperties.Local localCfg = new KeyManagementProperties.Local();
        localCfg.setKeyStorePath(path);
        localCfg.setAutoGenerate(true);

        QuantumKeyService ks = new QuantumKeyService(new LocalDevKeyProvider(localCfg), new KeyRegistry());
        ks.bootstrap();

        byte[] kyberBefore     = ks.getActiveKyberKeyPair().getPublic().getEncoded();
        byte[] ecBefore        = ks.getActiveEcKeyPair().getPublic().getEncoded();
        byte[] dilithiumBefore = ks.getActiveDilithiumKeyPair().getPublic().getEncoded();

        KeyRotationManager rotationManager = new KeyRotationManager(ks, new KeyManagementProperties());
        rotationManager.triggerRotationNow();

        assertThat(ks.getActiveKyberKeyPair().getPublic().getEncoded()).isNotEqualTo(kyberBefore);
        assertThat(ks.getActiveEcKeyPair().getPublic().getEncoded()).isNotEqualTo(ecBefore);
        assertThat(ks.getActiveDilithiumKeyPair().getPublic().getEncoded()).isNotEqualTo(dilithiumBefore);
        System.out.println("✓ KeyRotationManager.triggerRotationNow() rotates all three managed keys, including Dilithium");
    }

    // ── /actuator/pqc key management reporting ───────────────────────────────

    @Test @Order(14)
    @DisplayName("Actuator: keyManagement block present with Phase 3, null without it")
    void actuatorReportsKeyManagementOnlyWhenPhase3Active() throws Exception {
        com.pqc.hybrid.handshake.HybridHandshakeOrchestrator ephemeralOrchestrator =
            new com.pqc.hybrid.handshake.HybridHandshakeOrchestrator(Optional.empty());
        PqcActuatorEndpoint withoutPhase3 = new PqcActuatorEndpoint(ephemeralOrchestrator, Optional.empty());
        assertThat(withoutPhase3.status().keyManagement()).isNull();

        String path = System.getProperty("java.io.tmpdir") +
                      "/qks-actuator-test-" + System.currentTimeMillis() + "/local-master.key";
        KeyManagementProperties.Local cfg = new KeyManagementProperties.Local();
        cfg.setKeyStorePath(path);
        cfg.setAutoGenerate(true);
        QuantumKeyService ks = new QuantumKeyService(new LocalDevKeyProvider(cfg), new KeyRegistry());
        ks.bootstrap();

        com.pqc.hybrid.handshake.HybridHandshakeOrchestrator kmsOrchestrator =
            new com.pqc.hybrid.handshake.HybridHandshakeOrchestrator(Optional.of(ks));
        PqcActuatorEndpoint withPhase3 = new PqcActuatorEndpoint(kmsOrchestrator, Optional.of(ks));

        java.util.Map<String, Object> keyManagement = withPhase3.status().keyManagement();
        assertThat(keyManagement).isNotNull();
        assertThat(keyManagement.get("provider")).isEqualTo("local");
        assertThat(keyManagement.get("providerHealthy")).isEqualTo(true);
        assertThat(keyManagement.get("keys")).isNotNull();
        System.out.println("✓ /actuator/pqc keyManagement: null without Phase 3, populated with it");
    }

    // ── QuantumKeyService.retireDeprecated() ──────────────────────────────────

    @Test @Order(15)
    @DisplayName("QuantumKeyService.retireDeprecated(): moves DEPRECATED versions to RETIRED, leaves ACTIVE untouched")
    void retireDeprecatedTransitionsStatus() throws Exception {
        String path = System.getProperty("java.io.tmpdir") +
                      "/qks-retire-test-" + System.currentTimeMillis() + "/local-master.key";
        KeyManagementProperties.Local cfg = new KeyManagementProperties.Local();
        cfg.setKeyStorePath(path);
        cfg.setAutoGenerate(true);

        QuantumKeyService ks = new QuantumKeyService(new LocalDevKeyProvider(cfg), new KeyRegistry());
        ks.bootstrap();
        ks.rotate(QuantumKeyService.KEY_KYBER); // v1 -> DEPRECATED, v2 -> ACTIVE

        assertThat(ks.getRegistry().findByVersion(QuantumKeyService.KEY_KYBER, 1).orElseThrow().getStatus())
            .isEqualTo(KeyVersion.Status.DEPRECATED);

        ks.retireDeprecated(QuantumKeyService.KEY_KYBER);

        assertThat(ks.getRegistry().findByVersion(QuantumKeyService.KEY_KYBER, 1).orElseThrow().getStatus())
            .isEqualTo(KeyVersion.Status.RETIRED);
        // The current ACTIVE version must be unaffected by retiring the old one
        assertThat(ks.getRegistry().getActive(QuantumKeyService.KEY_KYBER).getVersion()).isEqualTo(2);
        System.out.println("✓ retireDeprecated(): v1 DEPRECATED -> RETIRED, v2 stays ACTIVE");
    }

    @Test @Order(16)
    @DisplayName("QuantumKeyService.retireDeprecated(): is a no-op when there are no DEPRECATED versions")
    void retireDeprecatedNoOpWithoutDeprecatedVersions() throws Exception {
        String path = System.getProperty("java.io.tmpdir") +
                      "/qks-retire-noop-test-" + System.currentTimeMillis() + "/local-master.key";
        KeyManagementProperties.Local cfg = new KeyManagementProperties.Local();
        cfg.setKeyStorePath(path);
        cfg.setAutoGenerate(true);

        QuantumKeyService ks = new QuantumKeyService(new LocalDevKeyProvider(cfg), new KeyRegistry());
        ks.bootstrap(); // only one ACTIVE version exists — nothing DEPRECATED yet

        ks.retireDeprecated(QuantumKeyService.KEY_KYBER); // must not throw or touch the ACTIVE version

        assertThat(ks.getRegistry().getActive(QuantumKeyService.KEY_KYBER).getStatus())
            .isEqualTo(KeyVersion.Status.ACTIVE);
        System.out.println("✓ retireDeprecated(): no-op when nothing is DEPRECATED");
    }

    // ── WrappedKeyMaterial equals()/hashCode() — records with byte[] fields ──

    @Test @Order(17)
    @DisplayName("WrappedKeyMaterial: two instances with identical content are equal (content, not reference)")
    void wrappedKeyMaterialContentEquality() {
        byte[] bytes1 = {1, 2, 3, 4};
        byte[] bytes2 = {1, 2, 3, 4}; // same content, different array instance
        java.time.Instant now = java.time.Instant.now();

        WrappedKeyMaterial a = new WrappedKeyMaterial("key-1", 1, bytes1, "AES/GCM/NoPadding", "local", "", now);
        WrappedKeyMaterial b = new WrappedKeyMaterial("key-1", 1, bytes2, "AES/GCM/NoPadding", "local", "", now);

        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
        System.out.println("✓ WrappedKeyMaterial: content-based equals/hashCode, not reference-based");
    }

    @Test @Order(18)
    @DisplayName("WrappedKeyMaterial: differing wrappedBytes content makes instances unequal")
    void wrappedKeyMaterialContentInequality() {
        java.time.Instant now = java.time.Instant.now();
        WrappedKeyMaterial a = new WrappedKeyMaterial("key-1", 1, new byte[]{1, 2, 3}, "AES", "local", "", now);
        WrappedKeyMaterial b = new WrappedKeyMaterial("key-1", 1, new byte[]{9, 9, 9}, "AES", "local", "", now);

        assertThat(a).isNotEqualTo(b);
        System.out.println("✓ WrappedKeyMaterial: different wrappedBytes content -> not equal");
    }
}
