package com.pqc.hybrid.actuator;

import com.pqc.hybrid.handshake.*;
import com.pqc.hybrid.keymanagement.service.QuantumKeyService;
import org.springframework.boot.actuate.endpoint.annotation.*;
import org.springframework.stereotype.Component;

import java.security.Security;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Spring Boot Actuator endpoint for PQC monitoring.
 * Accessible at: GET /actuator/pqc
 *
 * Sub-paths:
 *   GET  /actuator/pqc              — full status report
 *   GET  /actuator/pqc/sessions     — list active session summaries
 *   GET  /actuator/pqc/algorithms   — algorithm availability
 *   POST /actuator/pqc/benchmark    — run performance benchmark
 *
 * When Phase 3 (key management) is configured, the status report also includes a
 * {@code keyManagement} block — provider name, health, and per-key version history
 * from {@link com.pqc.hybrid.keymanagement.registry.KeyRegistry#toSummary()}. It is
 * {@code null} when no QuantumKeyService bean is present (ephemeral keys).
 */
@Component
@Endpoint(id = "pqc")
public class PqcActuatorEndpoint {

    private final HybridHandshakeOrchestrator orchestrator;
    private final Optional<QuantumKeyService> quantumKeyService;

    public PqcActuatorEndpoint(HybridHandshakeOrchestrator orchestrator,
                                Optional<QuantumKeyService> quantumKeyService) {
        this.orchestrator      = orchestrator;
        this.quantumKeyService = quantumKeyService;
    }

    @ReadOperation
    public PqcStatusReport status() {
        Map<String, HandshakeSession> all = orchestrator.getSessions();

        long total     = all.size();
        long safeSessions = all.values().stream().filter(HandshakeSession::isQuantumSafe).count();
        double safetyPct  = total > 0 ? safeSessions * 100.0 / total : 0.0;

        Map<String, Long> byMode = all.values().stream()
            .collect(Collectors.groupingBy(s -> s.getCipherMode().name(), Collectors.counting()));

        Map<String, Double> avgMs = all.values().stream()
            .collect(Collectors.groupingBy(
                s -> s.getCipherMode().name(),
                Collectors.averagingDouble(HandshakeSession::getHandshakeDurationMs)));

        return new PqcStatusReport(
            algorithmStatus(), total, safeSessions, safetyPct, byMode, avgMs,
            Runtime.version().toString(),
            Security.getProvider("BC")    != null ? "BouncyCastle"    : "not loaded",
            Security.getProvider("BCPQC") != null ? "BouncyCastlePQC" : "not loaded",
            keyManagementStatus()
        );
    }

    private Map<String, Object> keyManagementStatus() {
        if (quantumKeyService.isEmpty()) return null;
        QuantumKeyService qs = quantumKeyService.get();

        Map<String, Object> status = new LinkedHashMap<>();
        status.put("provider",         qs.getProviderName());
        status.put("providerHealthy",  qs.isProviderHealthy());
        status.put("keys",             qs.getRegistry().toSummary());
        return status;
    }

    @ReadOperation
    public Object detail(@Selector String section) {
        return switch (section) {
            case "sessions"   -> orchestrator.getSessions().values().stream()
                                    .map(HandshakeSession::toSummary).collect(Collectors.toList());
            case "algorithms" -> algorithmStatus();
            default           -> Map.of("error", "Unknown section: " + section,
                                        "valid", List.of("sessions", "algorithms"));
        };
    }

    @WriteOperation
    public BenchmarkReport benchmark() throws Exception {
        int runs = 20;
        Map<String, BenchmarkEntry> results = new LinkedHashMap<>();

        for (CipherMode mode : List.of(CipherMode.CLASSICAL, CipherMode.PQC_ONLY, CipherMode.HYBRID)) {
            long total = 0;
            for (int i = 0; i < runs; i++) {
                HandshakeSession s = orchestrator.orchestrate(capabilityFor(mode));
                total += s.getHandshakeDurationNs();
            }
            results.put(mode.name(), new BenchmarkEntry(
                mode.getDescription(), total / runs / 1_000_000.0, mode.isQuantumSafe()));
        }
        return new BenchmarkReport(results, runs);
    }

    private ClientCapability capabilityFor(CipherMode mode) {
        return switch (mode) {
            case HYBRID   -> ClientCapability.builder().pqcCapable(true).hybridCapable(true)
                              .supportedAlgorithms(Set.of("Kyber-768","Dilithium-3"))
                              .clientId("benchmark").build();
            case PQC_ONLY -> ClientCapability.builder().pqcCapable(true).hybridCapable(false)
                              .supportedAlgorithms(Set.of("Kyber-768"))
                              .clientId("benchmark").build();
            default       -> ClientCapability.builder().pqcCapable(false)
                              .clientId("benchmark").build();
        };
    }

    private Map<String, Object> algorithmStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("Kyber-768",       probeAlgorithm("Kyber",       "BCPQC"));
        status.put("Dilithium-3",     probeAlgorithm("Dilithium",   "BCPQC"));
        status.put("SPHINCS+",        probeAlgorithm("SPHINCSPlus", "BCPQC"));
        status.put("ECDHE-P384",      probeAlgorithm("ECDH",        "BC"));
        status.put("HmacSHA256-KDF",  probeAlgorithm("HmacSHA256",  "BC"));
        return status;
    }

    private Map<String, Object> probeAlgorithm(String algo, String provider) {
        try {
            java.security.KeyPairGenerator.getInstance(algo, provider);
            return Map.of("available", true, "provider", provider);
        } catch (Exception e) {
            try {
                javax.crypto.Mac.getInstance(algo, provider);
                return Map.of("available", true, "provider", provider);
            } catch (Exception e2) {
                return Map.of("available", false, "reason", e.getMessage());
            }
        }
    }

    public record PqcStatusReport(
        Map<String, Object> algorithmStatus,
        long                totalSessions,
        long                quantumSafeSessions,
        double              quantumSafetyPercent,
        Map<String, Long>   sessionsByMode,
        Map<String, Double> avgHandshakeMsByMode,
        String              javaVersion,
        String              classicalProvider,
        String              pqcProvider,
        Map<String, Object> keyManagement
    ) {}

    public record BenchmarkEntry(String description, double avgHandshakeMs, boolean quantumSafe) {}
    public record BenchmarkReport(Map<String, BenchmarkEntry> results, int runsPerMode) {}
}
