package com.pqc.hybrid.migration;

import com.pqc.hybrid.handshake.CipherMode;
import com.pqc.hybrid.handshake.HandshakeSession;
import com.pqc.hybrid.handshake.HybridHandshakeOrchestrator;
import com.pqc.hybrid.migration.config.RsaMigrationProperties;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.*;

import java.security.Security;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for Phase 5 — RSA Migration Bridge.
 *
 * All tests run without a Spring context — direct unit tests of the bridge
 * service, RSA converter, and mode resolution logic.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class RsaMigrationBridgeTest {

    private static RsaKeyConverter             rsaConverter;
    private static HybridHandshakeOrchestrator orchestrator;
    private static RsaMigrationProperties      props;
    private static RsaKyberBridgeService       bridgeService;

    @BeforeAll
    static void setup() throws Exception {
        if (Security.getProvider("BC")    == null) Security.insertProviderAt(new BouncyCastleProvider(),    1);
        if (Security.getProvider("BCPQC") == null) Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);

        rsaConverter  = new RsaKeyConverter();
        orchestrator  = new HybridHandshakeOrchestrator(Optional.empty());
        props         = new RsaMigrationProperties();
        bridgeService = new RsaKyberBridgeService(rsaConverter, orchestrator, props);
    }

    // ── RSA key converter ─────────────────────────────────────────

    @Test @Order(1)
    @DisplayName("RSA-2048 key wrap/unwrap round-trip recovers original bytes")
    void rsaWrapUnwrapRoundTrip() throws Exception {
        byte[] original = new byte[32];
        for (int i = 0; i < 32; i++) original[i] = (byte) i;

        byte[] wrapped   = rsaConverter.wrapKeyMaterial(original);
        byte[] recovered = rsaConverter.unwrapKeyMaterial(wrapped);

        assertThat(recovered).isEqualTo(original);
        assertThat(wrapped.length).isGreaterThan(32); // OAEP adds overhead
        System.out.printf("✓ RSA wrap: %d bytes plaintext → %d bytes ciphertext%n",
                original.length, wrapped.length);
    }

    @Test @Order(2)
    @DisplayName("RSA converter produces different ciphertext each call (OAEP randomisation)")
    void rsaOaepIsRandomised() throws Exception {
        byte[] key = new byte[32];

        byte[] wrapped1 = rsaConverter.wrapKeyMaterial(key);
        byte[] wrapped2 = rsaConverter.wrapKeyMaterial(key);

        assertThat(wrapped1).isNotEqualTo(wrapped2); // OAEP is probabilistic
        System.out.println("✓ RSA-OAEP: two wraps of same plaintext produce different ciphertext");
    }

    // ── RSA_ONLY mode ──────────────────────────────────────────────

    @Test @Order(3)
    @DisplayName("RSA_ONLY session uses CLASSICAL cipher mode and is NOT quantum-safe")
    void rsaOnlySessionMode() throws Exception {
        HandshakeSession session = bridgeService.establishSession("legacy-svc", MigrationMode.RSA_ONLY);

        assertThat(session.getCipherMode()).isEqualTo(CipherMode.CLASSICAL);
        assertThat(session.isQuantumSafe()).isFalse();
        assertThat(session.getClassicalAlgorithm()).isEqualTo("RSA-2048-OAEP");
        assertThat(session.getPqcKemAlgorithm()).isEqualTo("none");
        assertThat(session.getSessionKeyMaterial()).hasSize(32);
        System.out.println("✓ RSA_ONLY: CLASSICAL mode, not quantum-safe, 32-byte session key");
    }

    @Test @Order(4)
    @DisplayName("RSA_ONLY session has a non-empty session ID")
    void rsaOnlySessionHasId() throws Exception {
        HandshakeSession session = bridgeService.establishSession("legacy-svc", MigrationMode.RSA_ONLY);
        assertThat(session.getSessionId()).isNotBlank();
        assertThat(session.getClientId()).isEqualTo("legacy-svc");
        System.out.println("✓ RSA_ONLY session ID: " + session.getSessionId());
    }

    // ── PQC_ONLY mode ──────────────────────────────────────────────

    @Test @Order(5)
    @DisplayName("PQC_ONLY session uses HYBRID mode and IS quantum-safe")
    void pqcOnlySessionMode() throws Exception {
        HandshakeSession session = bridgeService.establishSession("modern-svc", MigrationMode.PQC_ONLY);

        assertThat(session.getCipherMode()).isEqualTo(CipherMode.HYBRID);
        assertThat(session.isQuantumSafe()).isTrue();
        assertThat(session.getPqcKemAlgorithm()).isEqualTo("Kyber-768");
        assertThat(session.getSessionKeyMaterial()).hasSize(32);
        System.out.printf("✓ PQC_ONLY: HYBRID mode, quantum-safe, algo=%s%n", session.getPqcKemAlgorithm());
    }

    // ── BRIDGE mode ────────────────────────────────────────────────

    @Test @Order(6)
    @DisplayName("BRIDGE with rollout=100% always produces a quantum-safe session")
    void bridgeFullRolloutAlwaysPqc() throws Exception {
        props.setRolloutPercentage(100);
        props.setDefaultMode(MigrationMode.BRIDGE);

        for (int i = 0; i < 5; i++) {
            HandshakeSession session = bridgeService.establishSession("bridge-client-" + i, MigrationMode.BRIDGE);
            assertThat(session.isQuantumSafe()).isTrue();
        }
        System.out.println("✓ BRIDGE rollout=100%: all 5 sessions quantum-safe");
    }

    @Test @Order(7)
    @DisplayName("BRIDGE with rollout=0% always falls back to RSA (not quantum-safe)")
    void bridgeZeroRolloutAlwaysRsa() throws Exception {
        RsaMigrationProperties zeroProps = new RsaMigrationProperties();
        zeroProps.setRolloutPercentage(0);
        RsaKyberBridgeService zeroService =
                new RsaKyberBridgeService(rsaConverter, orchestrator, zeroProps);

        for (int i = 0; i < 5; i++) {
            HandshakeSession session = zeroService.establishSession("legacy-" + i, MigrationMode.BRIDGE);
            assertThat(session.isQuantumSafe()).isFalse();
            assertThat(session.getCipherMode()).isEqualTo(CipherMode.CLASSICAL);
        }
        System.out.println("✓ BRIDGE rollout=0%: all 5 sessions RSA fallback (not quantum-safe)");
    }

    // ── Per-service overrides ──────────────────────────────────────

    @Test @Order(8)
    @DisplayName("Per-service override forces RSA_ONLY even when defaultMode=PQC_ONLY")
    void perServiceOverrideForcesRsa() throws Exception {
        RsaMigrationProperties overrideProps = new RsaMigrationProperties();
        overrideProps.setDefaultMode(MigrationMode.PQC_ONLY);
        overrideProps.setServiceOverrides(Map.of("billing-legacy", MigrationMode.RSA_ONLY));

        RsaKyberBridgeService overrideService =
                new RsaKyberBridgeService(rsaConverter, orchestrator, overrideProps);

        // billing-legacy → RSA_ONLY override wins
        HandshakeSession rsaSession = overrideService.establishSession("billing-legacy", MigrationMode.PQC_ONLY);
        assertThat(rsaSession.isQuantumSafe()).isFalse();
        assertThat(rsaSession.getCipherMode()).isEqualTo(CipherMode.CLASSICAL);

        // different client → default PQC_ONLY applies
        HandshakeSession pqcSession = overrideService.establishSession("auth-svc", MigrationMode.PQC_ONLY);
        assertThat(pqcSession.isQuantumSafe()).isTrue();

        System.out.println("✓ Per-service override: billing-legacy→RSA, auth-svc→PQC");
    }

    @Test @Order(9)
    @DisplayName("Per-service override forces PQC_ONLY even when defaultMode=RSA_ONLY")
    void perServiceOverrideForcesPqc() throws Exception {
        RsaMigrationProperties overrideProps = new RsaMigrationProperties();
        overrideProps.setDefaultMode(MigrationMode.RSA_ONLY);
        overrideProps.setServiceOverrides(Map.of("migrated-svc", MigrationMode.PQC_ONLY));

        RsaKyberBridgeService overrideService =
                new RsaKyberBridgeService(rsaConverter, orchestrator, overrideProps);

        HandshakeSession session = overrideService.establishSession("migrated-svc", MigrationMode.RSA_ONLY);
        assertThat(session.isQuantumSafe()).isTrue();
        assertThat(session.getCipherMode()).isEqualTo(CipherMode.HYBRID);
        System.out.println("✓ Per-service override: migrated-svc forced to PQC_ONLY despite RSA_ONLY default");
    }

    // ── Statistics ─────────────────────────────────────────────────

    @Test @Order(10)
    @DisplayName("Stats correctly reflect RSA and PQC session counts")
    void statsTrackSessionCounts() throws Exception {
        RsaMigrationProperties statsProps = new RsaMigrationProperties();
        RsaKyberBridgeService statsService =
                new RsaKyberBridgeService(rsaConverter, orchestrator, statsProps);

        // 2 RSA-only sessions
        statsService.establishSession("rsa-a", MigrationMode.RSA_ONLY);
        statsService.establishSession("rsa-b", MigrationMode.RSA_ONLY);

        // 3 PQC-only sessions
        statsService.establishSession("pqc-a", MigrationMode.PQC_ONLY);
        statsService.establishSession("pqc-b", MigrationMode.PQC_ONLY);
        statsService.establishSession("pqc-c", MigrationMode.PQC_ONLY);

        MigrationStats stats = statsService.getStats();
        assertThat(stats.rsaSessions()).isEqualTo(2);
        assertThat(stats.pqcOnlySessions()).isEqualTo(3);
        assertThat(stats.totalSessions()).isEqualTo(5);
        assertThat(stats.quantumSafeSessions()).isEqualTo(3);
        assertThat(stats.pqcMigrationPercent()).isEqualTo(60.0);

        System.out.printf("✓ Stats: rsa=%d pqcOnly=%d total=%d migrated=%.0f%%%n",
                stats.rsaSessions(), stats.pqcOnlySessions(),
                stats.totalSessions(), stats.pqcMigrationPercent());
    }
}
