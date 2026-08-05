package com.pqc.hybrid.controller;

import com.pqc.hybrid.filter.HybridHandshakeFilter;
import com.pqc.hybrid.handshake.*;
import com.pqc.hybrid.signing.DilithiumSigningEngine;
import com.pqc.hybrid.signing.SphincsSigningEngine;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.KeyPair;
import java.util.Base64;
import java.util.Map;
import java.util.Set;

/**
 * Demo controller — shows all PQC features working end-to-end.
 *
 * Test with curl:
 *
 * # Classical (no PQC headers):
 *   curl http://localhost:8080/api/pqc/status
 *
 * # PQC Only:
 *   curl -H "X-PQC-Supported: Kyber-768" http://localhost:8080/api/pqc/status
 *
 * # Hybrid (maximum security):
 *   curl -H "X-PQC-Supported: Kyber-768,Dilithium-3" \
 *        -H "X-PQC-Hybrid: true" \
 *        http://localhost:8080/api/pqc/status
 *
 * # Session upgrade demo:
 *   curl http://localhost:8080/api/pqc/upgrade-demo
 *
 * # Dilithium signing demo:
 *   curl -X POST "http://localhost:8080/api/pqc/sign?message=HelloPQC"
 *
 * # SPHINCS+ signing demo:
 *   curl -X POST "http://localhost:8080/api/pqc/sign-sphincs?message=HelloPQC"
 */
@RestController
@RequestMapping("/api/pqc")
public class PqcDemoController {

    private final HybridHandshakeOrchestrator orchestrator;
    private final DilithiumSigningEngine      dilithium;
    private final SphincsSigningEngine        sphincs;

    public PqcDemoController(HybridHandshakeOrchestrator orchestrator,
                              DilithiumSigningEngine dilithium,
                              SphincsSigningEngine sphincs) {
        this.orchestrator = orchestrator;
        this.dilithium    = dilithium;
        this.sphincs      = sphincs;
    }

    /** Show negotiated cipher mode for this request */
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> status(HttpServletRequest request) {
        HandshakeSession session =
            (HandshakeSession) request.getAttribute(HybridHandshakeFilter.ATTR_SESSION);

        if (session == null) {
            return ResponseEntity.ok(Map.of("status", "filter-not-active"));
        }

        return ResponseEntity.ok(Map.of(
            "sessionId",           session.getSessionId(),
            "cipherMode",          session.getCipherMode().name(),
            "modeDescription",     session.getCipherMode().getDescription(),
            "quantumSafe",         session.isQuantumSafe(),
            "classicalAlgorithm",  session.getClassicalAlgorithm(),
            "pqcKemAlgorithm",     session.getPqcKemAlgorithm(),
            "handshakeDurationMs", session.getHandshakeDurationMs()
        ));
    }

    /** Simulate a session upgrade from CLASSICAL → HYBRID without reconnection */
    @GetMapping("/upgrade-demo")
    public ResponseEntity<Map<String, Object>> upgradeDemo() throws Exception {
        // Step 1: Legacy client connects
        HandshakeSession classical = orchestrator.orchestrate(
            ClientCapability.builder().pqcCapable(false).clientId("upgrading-client").build());

        // Step 2: Same client later sends PQC headers → upgrade without reconnecting
        HandshakeSession upgraded = orchestrator.upgradeSession(
            classical.getSessionId(),
            ClientCapability.builder()
                .pqcCapable(true).hybridCapable(true)
                .supportedAlgorithms(Set.of("Kyber-768", "Dilithium-3"))
                .clientId("upgrading-client").build()
        );

        return ResponseEntity.ok(Map.of(
            "before",   classical.toSummary(),
            "after",    upgraded.toSummary(),
            "upgraded", upgraded.getCipherMode() != classical.getCipherMode()
        ));
    }

    /** Demonstrate real Dilithium-3 signing */
    @PostMapping("/sign")
    public ResponseEntity<Map<String, Object>> signWithDilithium(
            @RequestParam(defaultValue = "Hello PQC") String message) throws Exception {

        KeyPair kp        = dilithium.generateKeyPair();
        byte[] signature  = dilithium.signString(kp.getPrivate(), message);
        boolean verified  = dilithium.verifyString(kp.getPublic(), message, signature);

        return ResponseEntity.ok(Map.of(
            "algorithm",      "Dilithium-3 (ML-DSA-65)",
            "message",        message,
            "signatureBytes", signature.length,
            "signatureB64",   Base64.getEncoder().encodeToString(signature).substring(0, 32) + "...",
            "verified",       verified,
            "publicKeyBytes", kp.getPublic().getEncoded().length
        ));
    }

    /** Demonstrate real SPHINCS+ signing */
    @PostMapping("/sign-sphincs")
    public ResponseEntity<Map<String, Object>> signWithSphincs(
            @RequestParam(defaultValue = "Hello PQC") String message) throws Exception {

        long start       = System.nanoTime();
        KeyPair kp       = sphincs.generateKeyPair();
        byte[] signature = sphincs.signString(kp.getPrivate(), message);
        boolean verified = sphincs.verifyString(kp.getPublic(), message, signature);
        long ms          = (System.nanoTime() - start) / 1_000_000;

        return ResponseEntity.ok(Map.of(
            "algorithm",      "SPHINCS+-SHA2-128f (SLH-DSA)",
            "message",        message,
            "signatureBytes", signature.length,
            "signatureB64",   Base64.getEncoder().encodeToString(signature).substring(0, 32) + "...",
            "verified",       verified,
            "publicKeyBytes", kp.getPublic().getEncoded().length,
            "totalDurationMs", ms
        ));
    }
}
