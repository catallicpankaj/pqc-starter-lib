package com.pqc.hybrid.keymanagement.rotation;

import com.pqc.hybrid.keymanagement.api.KeyVersion;
import com.pqc.hybrid.keymanagement.config.KeyManagementProperties;
import com.pqc.hybrid.keymanagement.providers.LocalDevKeyProvider;
import com.pqc.hybrid.keymanagement.registry.KeyRegistry;
import com.pqc.hybrid.keymanagement.service.QuantumKeyService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.*;

import java.security.Security;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for {@link KeyRotationManager}'s age-threshold decision logic — the boundary
 * between "leave this key alone" and "rotate/retire it now", which
 * {@link com.pqc.hybrid.keymanagement.service.QuantumKeyService}'s own rotate()/
 * retireDeprecated() tests don't exercise (those test the mechanics of rotation
 * itself, not whether KeyRotationManager decides to trigger it).
 *
 * KeyVersion's createdAt/deprecatedAt are normally stamped at Instant.now() and have
 * no production setter — KeyVersion.Builder.createdAt() exists purely so these tests
 * can simulate an aged key without sleeping in real time.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class KeyRotationManagerTest {

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BC")    == null) Security.insertProviderAt(new BouncyCastleProvider(),    1);
        if (Security.getProvider("BCPQC") == null) Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);
    }

    private QuantumKeyService freshBootstrappedService(String testName) throws Exception {
        String path = System.getProperty("java.io.tmpdir") +
                      "/rotation-mgr-test-" + testName + "-" + System.currentTimeMillis() + "/local-master.key";
        KeyManagementProperties.Local localCfg = new KeyManagementProperties.Local();
        localCfg.setKeyStorePath(path);
        localCfg.setAutoGenerate(true);

        QuantumKeyService ks = new QuantumKeyService(new LocalDevKeyProvider(localCfg), new KeyRegistry());
        ks.bootstrap();
        return ks;
    }

    /** Replaces the currently ACTIVE version of keyId with a copy whose createdAt is artificially aged. */
    private void ageActiveKey(QuantumKeyService ks, String keyId, int ageDays) {
        KeyVersion active = ks.getRegistry().getActive(keyId);
        KeyVersion aged = KeyVersion.builder()
            .keyId(active.getKeyId())
            .version(active.getVersion())
            .algorithm(active.getAlgorithm())
            .publicKey(active.getPublicKey())
            .wrappedPrivateKey(active.getWrappedPrivateKey())
            .status(KeyVersion.Status.ACTIVE)
            .createdAt(Instant.now().minus(ageDays, ChronoUnit.DAYS))
            .build();
        ks.getRegistry().register(aged);
    }

    /** Replaces a DEPRECATED version with a copy whose deprecatedAt is artificially aged. */
    private void ageDeprecatedKey(QuantumKeyService ks, String keyId, int version, int ageDaysSinceDeprecation) {
        KeyVersion deprecated = ks.getRegistry().findByVersion(keyId, version).orElseThrow();
        KeyVersion aged = KeyVersion.builder()
            .keyId(deprecated.getKeyId())
            .version(deprecated.getVersion())
            .algorithm(deprecated.getAlgorithm())
            .publicKey(deprecated.getPublicKey())
            .wrappedPrivateKey(deprecated.getWrappedPrivateKey())
            .status(KeyVersion.Status.DEPRECATED)
            .createdAt(deprecated.getCreatedAt())
            .deprecatedAt(Instant.now().minus(ageDaysSinceDeprecation, ChronoUnit.DAYS))
            .build();
        ks.getRegistry().register(aged);
    }

    // ── Rotation age threshold ────────────────────────────────────────────

    @Test @Order(1)
    @DisplayName("scheduledRotationCheck: does NOT rotate a key younger than the interval")
    void doesNotRotateYoungKey() throws Exception {
        QuantumKeyService ks = freshBootstrappedService("young");
        // key was just bootstrapped — createdAt is "now", well under a 90-day interval

        KeyManagementProperties props = new KeyManagementProperties();
        props.getRotation().setEnabled(true);
        props.getRotation().setIntervalDays(90);

        new KeyRotationManager(ks, props).scheduledRotationCheck();

        assertThat(ks.getRegistry().latestVersion(QuantumKeyService.KEY_KYBER)).isEqualTo(1);
        System.out.println("✓ Young key (age ~0d, interval=90d) not rotated");
    }

    @Test @Order(2)
    @DisplayName("scheduledRotationCheck: DOES rotate a key older than the interval")
    void rotatesOldKey() throws Exception {
        QuantumKeyService ks = freshBootstrappedService("old");
        ageActiveKey(ks, QuantumKeyService.KEY_KYBER, 100); // older than 90-day interval

        KeyManagementProperties props = new KeyManagementProperties();
        props.getRotation().setEnabled(true);
        props.getRotation().setIntervalDays(90);

        new KeyRotationManager(ks, props).scheduledRotationCheck();

        assertThat(ks.getRegistry().latestVersion(QuantumKeyService.KEY_KYBER)).isEqualTo(2);
        assertThat(ks.getRegistry().getActive(QuantumKeyService.KEY_KYBER).getVersion()).isEqualTo(2);
        System.out.println("✓ Aged key (age=100d, interval=90d) rotated to v2");
    }

    @Test @Order(3)
    @DisplayName("scheduledRotationCheck: a key exactly at the interval boundary IS rotated (>=, not >)")
    void rotatesAtExactBoundary() throws Exception {
        QuantumKeyService ks = freshBootstrappedService("boundary");
        ageActiveKey(ks, QuantumKeyService.KEY_KYBER, 90); // exactly the interval

        KeyManagementProperties props = new KeyManagementProperties();
        props.getRotation().setEnabled(true);
        props.getRotation().setIntervalDays(90);

        new KeyRotationManager(ks, props).scheduledRotationCheck();

        assertThat(ks.getRegistry().latestVersion(QuantumKeyService.KEY_KYBER)).isEqualTo(2);
        System.out.println("✓ Key at exactly the interval boundary (age=90d, interval=90d) rotated");
    }

    // ── Retirement age threshold ──────────────────────────────────────────

    @Test @Order(4)
    @DisplayName("scheduledRotationCheck: does NOT retire a deprecated key inside the deprecation window")
    void doesNotRetireRecentlyDeprecatedKey() throws Exception {
        QuantumKeyService ks = freshBootstrappedService("recent-deprecated");
        ks.rotate(QuantumKeyService.KEY_KYBER); // v1 -> DEPRECATED, v2 -> ACTIVE
        ageDeprecatedKey(ks, QuantumKeyService.KEY_KYBER, 1, 1); // deprecated 1 day ago

        KeyManagementProperties props = new KeyManagementProperties();
        props.getRotation().setEnabled(true);
        props.getRotation().setIntervalDays(9999); // don't also trigger a new rotation
        props.getRotation().setDeprecationWindowDays(7);

        new KeyRotationManager(ks, props).scheduledRotationCheck();

        KeyVersion v1 = ks.getRegistry().findByVersion(QuantumKeyService.KEY_KYBER, 1).orElseThrow();
        assertThat(v1.getStatus()).isEqualTo(KeyVersion.Status.DEPRECATED);
        System.out.println("✓ Deprecated key inside the 7-day window (1d elapsed) not yet retired");
    }

    @Test @Order(5)
    @DisplayName("scheduledRotationCheck: DOES retire a deprecated key past the deprecation window")
    void retiresOldDeprecatedKey() throws Exception {
        QuantumKeyService ks = freshBootstrappedService("old-deprecated");
        ks.rotate(QuantumKeyService.KEY_KYBER); // v1 -> DEPRECATED, v2 -> ACTIVE
        ageDeprecatedKey(ks, QuantumKeyService.KEY_KYBER, 1, 10); // deprecated 10 days ago

        KeyManagementProperties props = new KeyManagementProperties();
        props.getRotation().setEnabled(true);
        props.getRotation().setIntervalDays(9999); // don't also trigger a new rotation
        props.getRotation().setDeprecationWindowDays(7);

        new KeyRotationManager(ks, props).scheduledRotationCheck();

        KeyVersion v1 = ks.getRegistry().findByVersion(QuantumKeyService.KEY_KYBER, 1).orElseThrow();
        assertThat(v1.getStatus()).isEqualTo(KeyVersion.Status.RETIRED);
        // The current ACTIVE key is untouched by retirement of the old deprecated version
        assertThat(ks.getRegistry().getActive(QuantumKeyService.KEY_KYBER).getVersion()).isEqualTo(2);
        System.out.println("✓ Deprecated key past the 7-day window (10d elapsed) retired");
    }

    // ── Master switch ──────────────────────────────────────────────────────

    @Test @Order(6)
    @DisplayName("scheduledRotationCheck: no-ops entirely when rotation.enabled=false, even for a very old key")
    void noOpsWhenRotationDisabled() throws Exception {
        QuantumKeyService ks = freshBootstrappedService("disabled");
        ageActiveKey(ks, QuantumKeyService.KEY_KYBER, 9999); // absurdly old

        KeyManagementProperties props = new KeyManagementProperties();
        props.getRotation().setEnabled(false); // master switch off
        props.getRotation().setIntervalDays(1);

        new KeyRotationManager(ks, props).scheduledRotationCheck();

        assertThat(ks.getRegistry().latestVersion(QuantumKeyService.KEY_KYBER)).isEqualTo(1);
        System.out.println("✓ rotation.enabled=false skips the check entirely, regardless of key age");
    }
}
