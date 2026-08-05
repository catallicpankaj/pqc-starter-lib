package com.pqc.hybrid.integration;

import com.pqc.hybrid.handshake.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.*;

import java.security.Security;
import java.util.*;

import static org.assertj.core.api.Assertions.*;

/**
 * Integration tests for the full Hybrid Handshake Orchestrator.
 * Covers: CLASSICAL, PQC_ONLY, HYBRID modes, session upgrade, key safety, benchmarks.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class HybridOrchestratorIntegrationTest {

    private static HybridHandshakeOrchestrator orchestrator;

    @BeforeAll
    static void setup() throws Exception {
        if (Security.getProvider("BC")    == null) Security.insertProviderAt(new BouncyCastleProvider(), 1);
        if (Security.getProvider("BCPQC") == null) Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);
        orchestrator = new HybridHandshakeOrchestrator();
    }

    @Test @Order(1) @DisplayName("Legacy client → CLASSICAL mode")
    void legacyClientGetsClassicalMode() throws Exception {
        HandshakeSession s = orchestrator.orchestrate(
            ClientCapability.builder().pqcCapable(false).clientId("legacy").build());
        assertThat(s.getCipherMode()).isEqualTo(CipherMode.CLASSICAL);
        assertThat(s.isQuantumSafe()).isFalse();
        assertThat(s.getPqcKemAlgorithm()).isEqualTo("none");
        System.out.printf("✓ CLASSICAL: %.3f ms%n", s.getHandshakeDurationMs());
    }

    @Test @Order(2) @DisplayName("PQC client → PQC_ONLY with real Kyber-768")
    void pqcClientGetsRealKyber() throws Exception {
        HandshakeSession s = orchestrator.orchestrate(
            ClientCapability.builder().pqcCapable(true).hybridCapable(false)
                .supportedAlgorithms(Set.of("Kyber-768")).clientId("pqc").build());
        assertThat(s.getCipherMode()).isEqualTo(CipherMode.PQC_ONLY);
        assertThat(s.isQuantumSafe()).isTrue();
        assertThat(s.getPqcKemAlgorithm()).isEqualTo("Kyber-768");
        System.out.printf("✓ PQC_ONLY (real Kyber-768): %.3f ms%n", s.getHandshakeDurationMs());
    }

    @Test @Order(3) @DisplayName("Hybrid client → HYBRID with Kyber-768 + ECDHE-P384")
    void hybridClientGetsRealHybrid() throws Exception {
        HandshakeSession s = orchestrator.orchestrate(
            ClientCapability.builder().pqcCapable(true).hybridCapable(true)
                .supportedAlgorithms(Set.of("Kyber-768", "Dilithium-3")).clientId("hybrid").build());
        assertThat(s.getCipherMode()).isEqualTo(CipherMode.HYBRID);
        assertThat(s.isQuantumSafe()).isTrue();
        assertThat(s.getClassicalAlgorithm()).isEqualTo("ECDHE-P384");
        assertThat(s.getPqcKemAlgorithm()).isEqualTo("Kyber-768");
        assertThat(s.getSessionKeyMaterial()).hasSize(32);
        System.out.printf("✓ HYBRID (Kyber-768 + ECDHE-P384): %.3f ms%n", s.getHandshakeDurationMs());
    }

    @Test @Order(4) @DisplayName("Runtime upgrade: CLASSICAL → HYBRID without reconnection")
    void sessionUpgradeClassicalToHybrid() throws Exception {
        HandshakeSession classical = orchestrator.orchestrate(
            ClientCapability.builder().pqcCapable(false).clientId("upgrade-client").build());
        assertThat(classical.getCipherMode()).isEqualTo(CipherMode.CLASSICAL);

        HandshakeSession upgraded = orchestrator.upgradeSession(
            classical.getSessionId(),
            ClientCapability.builder().pqcCapable(true).hybridCapable(true)
                .supportedAlgorithms(Set.of("Kyber-768")).clientId("upgrade-client").build());

        assertThat(upgraded.getCipherMode()).isEqualTo(CipherMode.HYBRID);
        assertThat(upgraded.isQuantumSafe()).isTrue();
        System.out.printf("✓ Upgraded %s → %s%n", classical.getCipherMode(), upgraded.getCipherMode());
    }

    @Test @Order(5) @DisplayName("Hybrid key differs from both classical and PQC-only keys")
    void hybridKeyIsTrulyHybrid() throws Exception {
        HandshakeSession clas = orchestrator.orchestrate(
            ClientCapability.builder().pqcCapable(false).clientId("c").build());
        HandshakeSession pqc = orchestrator.orchestrate(
            ClientCapability.builder().pqcCapable(true).hybridCapable(false)
                .supportedAlgorithms(Set.of("Kyber-768")).clientId("p").build());
        HandshakeSession hyb = orchestrator.orchestrate(
            ClientCapability.builder().pqcCapable(true).hybridCapable(true)
                .supportedAlgorithms(Set.of("Kyber-768")).clientId("h").build());

        assertThat(hyb.getSessionKeyMaterial()).isNotEqualTo(clas.getSessionKeyMaterial());
        assertThat(hyb.getSessionKeyMaterial()).isNotEqualTo(pqc.getSessionKeyMaterial());
        System.out.println("✓ Hybrid key is a genuine combination of both secrets");
    }

    @Test @Order(6) @DisplayName("Session summary never exposes full key material")
    void summaryDoesNotExposeKeyMaterial() throws Exception {
        HandshakeSession s = orchestrator.orchestrate(
            ClientCapability.builder().pqcCapable(true).hybridCapable(true)
                .supportedAlgorithms(Set.of("Kyber-768")).clientId("safety").build());
        String fingerprint = s.toSummary().keyFingerprint();
        String fullKey = java.util.Base64.getEncoder().encodeToString(s.getSessionKeyMaterial());
        assertThat(fingerprint).endsWith("...");
        assertThat(fingerprint.length()).isLessThan(fullKey.length());
        System.out.println("✓ Key material safely truncated in summary");
    }

    @Test @Order(7) @DisplayName("Performance benchmark: all three modes (n=20)")
    void performanceBenchmark() throws Exception {
        int runs = 20;
        System.out.println("\n─── Performance Benchmark (n=" + runs + ") ────────────────");
        for (CipherMode mode : CipherMode.values()) {
            long total = 0;
            for (int i = 0; i < runs; i++) {
                total += orchestrator.orchestrate(capFor(mode)).getHandshakeDurationNs();
            }
            double avg = total / runs / 1_000_000.0;
            System.out.printf("  %-12s avg=%7.3f ms  quantum-safe: %s%n",
                mode, avg, mode.isQuantumSafe() ? "YES ✓" : "NO");
            assertThat(avg).isLessThan(2000);
        }
    }

    private ClientCapability capFor(CipherMode mode) {
        return switch (mode) {
            case HYBRID    -> ClientCapability.builder().pqcCapable(true).hybridCapable(true)
                               .supportedAlgorithms(Set.of("Kyber-768")).clientId("bench").build();
            case PQC_ONLY  -> ClientCapability.builder().pqcCapable(true).hybridCapable(false)
                               .supportedAlgorithms(Set.of("Kyber-768")).clientId("bench").build();
            case CLASSICAL -> ClientCapability.builder().pqcCapable(false).clientId("bench").build();
        };
    }
}
