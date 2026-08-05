package com.pqc.hybrid.migration;

import com.pqc.hybrid.handshake.HandshakeSession;
import com.pqc.hybrid.migration.config.RsaMigrationProperties;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Phase 5 — RSA Migration Bridge REST endpoints.
 *
 * Endpoints:
 *   POST /api/migration/bridge-handshake   — session using configured default mode
 *   POST /api/migration/simulate-legacy    — forces RSA-only path (legacy peer sim)
 *   POST /api/migration/simulate-pqc      — forces PQC-only path (migrated peer sim)
 *   GET  /api/migration/status            — live migration stats + rollout %
 *   GET  /api/migration/rsa-public-key    — server RSA public key metadata
 *
 * All session endpoints return a safe summary — no key material is exposed.
 */
@RestController
@RequestMapping("/api/migration")
public class RsaMigrationController {

    private final RsaKyberBridgeService  bridgeService;
    private final RsaMigrationProperties props;

    public RsaMigrationController(RsaKyberBridgeService bridgeService,
                                   RsaMigrationProperties props) {
        this.bridgeService = bridgeService;
        this.props         = props;
    }

    // ─────────────────────────────────────────────────────────────
    // Session endpoints
    // ─────────────────────────────────────────────────────────────

    /**
     * Bridge handshake using the configured default mode.
     * BRIDGE mode: PQC if rollout % allows, RSA otherwise.
     * Per-service override (serviceOverrides map) takes precedence.
     */
    @PostMapping("/bridge-handshake")
    ResponseEntity<Map<String, Object>> bridgeHandshake(
            @RequestParam(defaultValue = "demo-client") String clientId) throws Exception {

        HandshakeSession session = bridgeService.establishSession(clientId, props.getDefaultMode());
        return ResponseEntity.ok(sessionResponse(session, props.getDefaultMode().name()));
    }

    /**
     * Simulate a legacy RSA-only peer — always uses RSA-2048 OAEP.
     * Useful for testing backward compatibility during migration.
     */
    @PostMapping("/simulate-legacy")
    ResponseEntity<Map<String, Object>> simulateLegacy(
            @RequestParam(defaultValue = "legacy-client") String clientId) throws Exception {

        HandshakeSession session = bridgeService.establishSession(clientId, MigrationMode.RSA_ONLY);
        return ResponseEntity.ok(sessionResponse(session, "RSA_ONLY"));
    }

    /**
     * Simulate a fully-migrated PQC peer — always uses Kyber/Hybrid.
     * Useful for testing the PQC path in isolation.
     */
    @PostMapping("/simulate-pqc")
    ResponseEntity<Map<String, Object>> simulatePqc(
            @RequestParam(defaultValue = "pqc-client") String clientId) throws Exception {

        HandshakeSession session = bridgeService.establishSession(clientId, MigrationMode.PQC_ONLY);
        return ResponseEntity.ok(sessionResponse(session, "PQC_ONLY"));
    }

    // ─────────────────────────────────────────────────────────────
    // Observability endpoints
    // ─────────────────────────────────────────────────────────────

    /**
     * Live migration statistics.
     * Shows how many sessions went RSA vs. PQC and the current rollout %.
     */
    @GetMapping("/status")
    ResponseEntity<Map<String, Object>> status() {
        MigrationStats stats = bridgeService.getStats();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("phase",                 "Phase 5 — RSA Migration Bridge");
        body.put("defaultMode",           props.getDefaultMode().name());
        body.put("rolloutPercentage",     props.getRolloutPercentage() + "%");
        body.put("serviceOverrides",      props.getServiceOverrides());
        body.put("rsaSessions",           stats.rsaSessions());
        body.put("bridgeToPqcSessions",   stats.bridgeToPqcSessions());
        body.put("bridgeToRsaSessions",   stats.bridgeToRsaSessions());
        body.put("pqcOnlySessions",       stats.pqcOnlySessions());
        body.put("quantumSafeSessions",   stats.quantumSafeSessions());
        body.put("totalSessions",         stats.totalSessions());
        body.put("pqcMigrationPercent",   String.format("%.1f%%", stats.pqcMigrationPercent()));
        return ResponseEntity.ok(body);
    }

    /**
     * Server's RSA public key metadata.
     * In a real deployment legacy clients would fetch this to encrypt their session key.
     */
    @GetMapping("/rsa-public-key")
    ResponseEntity<Map<String, Object>> rsaPublicKey() {
        byte[] encoded = bridgeService.getRsaConverter().getServerPublicKey().getEncoded();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("algorithm",     "RSA-" + bridgeService.getRsaConverter().getKeyBits());
        body.put("format",        "X.509 SubjectPublicKeyInfo");
        body.put("encodedLength", encoded.length + " bytes");
        body.put("purpose",       "RSA-OAEP key transport — encrypt 32-byte session key with this key");
        return ResponseEntity.ok(body);
    }

    // ─────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────

    private Map<String, Object> sessionResponse(HandshakeSession session, String requestedMode) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("sessionId",            session.getSessionId());
        m.put("requestedMode",        requestedMode);
        m.put("negotiatedCipherMode", session.getCipherMode().name());
        m.put("quantumSafe",          session.isQuantumSafe());
        m.put("classicalAlgorithm",   session.getClassicalAlgorithm());
        m.put("pqcKemAlgorithm",      session.getPqcKemAlgorithm());
        m.put("handshakeDurationMs",  session.getHandshakeDurationNs() / 1_000_000.0);
        return m;
    }
}
