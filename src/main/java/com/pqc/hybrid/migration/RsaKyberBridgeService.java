package com.pqc.hybrid.migration;

import com.pqc.hybrid.handshake.CipherMode;
import com.pqc.hybrid.handshake.ClientCapability;
import com.pqc.hybrid.handshake.HandshakeSession;
import com.pqc.hybrid.handshake.HybridHandshakeOrchestrator;
import com.pqc.hybrid.migration.config.RsaMigrationProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

/**
 * RSA ↔ Kyber Migration Bridge — Phase 5 core service.
 *
 * Enables gradual, service-by-service migration from RSA-2048 to
 * Kyber-768 / Hybrid PQC without a hard cut-over. Three modes:
 *
 *   RSA_ONLY  — always use RSA-2048 OAEP key transport
 *               (legacy simulation and backward-compat testing)
 *
 *   BRIDGE    — PQC-preferred dual mode:
 *               · If rolloutPercentage allows → use Kyber/Hybrid
 *               · Otherwise → fall back to RSA for that peer
 *               · Per-service overrides take precedence over %
 *
 *   PQC_ONLY  — always use Kyber/Hybrid, refuses RSA path.
 *               Set once a service is fully migrated.
 *
 * Stats are tracked atomically so you can measure migration progress
 * live via GET /api/migration/status.
 */
public class RsaKyberBridgeService {

    private static final Logger log = LoggerFactory.getLogger(RsaKyberBridgeService.class);

    private final RsaKeyConverter             rsaConverter;
    private final HybridHandshakeOrchestrator orchestrator;
    private final RsaMigrationProperties      props;

    // Atomic counters — safe for concurrent requests
    private final AtomicLong rsaCount         = new AtomicLong();
    private final AtomicLong bridgeToPqcCount = new AtomicLong();
    private final AtomicLong bridgeToRsaCount = new AtomicLong();
    private final AtomicLong pqcOnlyCount     = new AtomicLong();

    private final SecureRandom rng = new SecureRandom();

    public RsaKyberBridgeService(RsaKeyConverter rsaConverter,
                                  HybridHandshakeOrchestrator orchestrator,
                                  RsaMigrationProperties props) {
        this.rsaConverter  = rsaConverter;
        this.orchestrator  = orchestrator;
        this.props         = props;
    }

    // ─────────────────────────────────────────────────────────────
    // PUBLIC API
    // ─────────────────────────────────────────────────────────────

    /**
     * Establish a migration-aware session.
     *
     * Resolution order:
     *   1. Per-service override in serviceOverrides (if clientId matches).
     *   2. Requested mode (typically the configured defaultMode).
     *
     * @param clientId       peer identifier (used for per-service overrides)
     * @param requestedMode  default mode to apply if no override exists
     * @return HandshakeSession with session key and mode metadata
     */
    public HandshakeSession establishSession(String clientId, MigrationMode requestedMode)
            throws Exception {
        MigrationMode effective = resolveMode(clientId, requestedMode);
        log.info("Bridge session: clientId={} requested={} effective={}", clientId, requestedMode, effective);

        return switch (effective) {
            case RSA_ONLY -> performRsaSession(clientId, false);
            case PQC_ONLY -> performPqcSession(clientId);
            case BRIDGE   -> performBridgeSession(clientId);
        };
    }

    /**
     * Snapshot of migration statistics.
     * Use GET /api/migration/status to expose these externally.
     */
    public MigrationStats getStats() {
        long rsa     = rsaCount.get();
        long bPqc    = bridgeToPqcCount.get();
        long bRsa    = bridgeToRsaCount.get();
        long pqcOnly = pqcOnlyCount.get();
        long total   = rsa + bPqc + bRsa + pqcOnly;
        long qsSessions = bPqc + pqcOnly;
        double pct   = total == 0 ? 0.0 : (qsSessions * 100.0 / total);
        return new MigrationStats(rsa, bPqc, bRsa, pqcOnly, total, pct);
    }

    public RsaKeyConverter getRsaConverter() { return rsaConverter; }

    // ─────────────────────────────────────────────────────────────
    // SESSION PATHS
    // ─────────────────────────────────────────────────────────────

    /**
     * RSA_ONLY path — RSA-2048 OAEP key transport.
     *
     * Full round-trip:
     *   Client side: generate 32-byte session key, wrap with server RSA public key.
     *   Server side: unwrap with RSA private key → recovers same 32 bytes.
     * The HandshakeSession is created with those 32 bytes as session key material.
     */
    private HandshakeSession performRsaSession(String clientId, boolean isBridgeFallback)
            throws Exception {
        long start = System.nanoTime();

        // Client side: generate 32-byte session key material, encrypt with server RSA pubkey
        byte[] sessionKeyMaterial = new byte[32];
        rng.nextBytes(sessionKeyMaterial);
        byte[] wrapped = rsaConverter.wrapKeyMaterial(sessionKeyMaterial);

        // Server side: decrypt → recovers same key material
        byte[] recovered = rsaConverter.unwrapKeyMaterial(wrapped);

        long durationNs = System.nanoTime() - start;
        log.info("[RSA-path] clientId={} wrappedSize={}B durationMs={}", clientId,
                wrapped.length, durationNs / 1_000_000.0);

        if (isBridgeFallback) bridgeToRsaCount.incrementAndGet();
        else                  rsaCount.incrementAndGet();

        return HandshakeSession.builder()
                .sessionId(generateSessionId())
                .cipherMode(CipherMode.CLASSICAL)
                .sessionKeyMaterial(recovered)
                .clientId(clientId)
                .classicalAlgorithm("RSA-2048-OAEP")
                .handshakeDurationNs(durationNs)
                .quantumSafe(false)
                .build();
    }

    /**
     * PQC_ONLY path — delegates to HybridHandshakeOrchestrator.
     * Client is assumed to support Kyber-768 + ECDHE-P384 (HYBRID mode).
     */
    private HandshakeSession performPqcSession(String clientId) throws Exception {
        pqcOnlyCount.incrementAndGet();
        ClientCapability cap = ClientCapability.builder()
                .clientId(clientId)
                .pqcCapable(true)
                .hybridCapable(true)
                .supportedAlgorithms(Set.of("Kyber-768", "Dilithium-3"))
                .protocolVersion(1)
                .build();
        return orchestrator.orchestrate(cap);
    }

    /**
     * BRIDGE path — PQC preferred, RSA fallback based on rolloutPercentage.
     *
     * rolloutPercentage = 100 → all sessions use PQC (fully rolled out)
     * rolloutPercentage = 0   → all sessions use RSA (rollout not started)
     * rolloutPercentage = 50  → 50 % PQC / 50 % RSA (canary rollout)
     */
    private HandshakeSession performBridgeSession(String clientId) throws Exception {
        boolean usePqc = (rng.nextInt(100) < props.getRolloutPercentage());
        if (usePqc) {
            log.debug("Bridge → PQC path (rollout={}%)", props.getRolloutPercentage());
            bridgeToPqcCount.incrementAndGet();
            // Return PQC session without double-counting in pqcOnlyCount
            ClientCapability cap = ClientCapability.builder()
                    .clientId(clientId)
                    .pqcCapable(true)
                    .hybridCapable(true)
                    .supportedAlgorithms(Set.of("Kyber-768", "Dilithium-3"))
                    .protocolVersion(1)
                    .build();
            return orchestrator.orchestrate(cap);
        } else {
            log.debug("Bridge → RSA fallback (rollout={}%)", props.getRolloutPercentage());
            return performRsaSession(clientId, true);
        }
    }

    // ─────────────────────────────────────────────────────────────
    // HELPERS
    // ─────────────────────────────────────────────────────────────

    private MigrationMode resolveMode(String clientId, MigrationMode requestedMode) {
        return props.getServiceOverrides().getOrDefault(clientId, requestedMode);
    }

    private String generateSessionId() {
        byte[] bytes = new byte[8];
        rng.nextBytes(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02X", b));
        return sb.toString();
    }
}
