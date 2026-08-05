package com.pqc.hybrid.filter;

import com.pqc.hybrid.handshake.ClientCapability;
import com.pqc.hybrid.handshake.HandshakeSession;
import com.pqc.hybrid.handshake.HybridHandshakeOrchestrator;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Servlet filter that intercepts every request and performs runtime PQC mode switching.
 *
 * Reads capability headers → orchestrates handshake → attaches session to request.
 *
 * Request headers parsed:
 *   X-PQC-Supported:   "Kyber-768,Dilithium-3"
 *   X-PQC-Hybrid:      "true"
 *   X-PQC-Version:     "1"
 *   X-PQC-Session:     "&lt;session-id&gt;"  (triggers upgrade path)
 *
 * Response headers set:
 *   X-PQC-Mode:        "HYBRID" | "PQC_ONLY" | "CLASSICAL"
 *   X-PQC-Session-Id:  "&lt;session-id&gt;"
 *   X-PQC-Quantum-Safe: "true" | "false"
 *   X-PQC-Algorithm:   "Kyber-768"
 *   X-PQC-Classical:   "ECDHE-P384"
 *
 * Request attributes set (for downstream Spring components):
 *   pqc.session        HandshakeSession object
 *   pqc.cipher.mode    CipherMode enum value
 *   pqc.quantum.safe   boolean
 */
@Component
@Order(1)
public class HybridHandshakeFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(HybridHandshakeFilter.class);

    public static final String ATTR_SESSION      = "pqc.session";
    public static final String ATTR_CIPHER_MODE  = "pqc.cipher.mode";
    public static final String ATTR_QUANTUM_SAFE = "pqc.quantum.safe";

    private final HybridHandshakeOrchestrator orchestrator;

    public HybridHandshakeFilter(HybridHandshakeOrchestrator orchestrator) {
        this.orchestrator = orchestrator;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest  request  = (HttpServletRequest)  req;
        HttpServletResponse response = (HttpServletResponse) res;

        try {
            ClientCapability capability = parseCapability(request);
            String existingSession      = request.getHeader(ClientCapability.HEADER_PQC_SESSION_ID);

            HandshakeSession session = (existingSession != null && !existingSession.isBlank())
                ? orchestrator.upgradeSession(existingSession, capability)
                : orchestrator.orchestrate(capability);

            // Attach to request for downstream use
            request.setAttribute(ATTR_SESSION,      session);
            request.setAttribute(ATTR_CIPHER_MODE,  session.getCipherMode());
            request.setAttribute(ATTR_QUANTUM_SAFE, session.isQuantumSafe());

            // Inform client of negotiated mode
            response.setHeader("X-PQC-Mode",         session.getCipherMode().name());
            response.setHeader("X-PQC-Session-Id",   session.getSessionId());
            response.setHeader("X-PQC-Quantum-Safe", String.valueOf(session.isQuantumSafe()));
            response.setHeader("X-PQC-Algorithm",    session.getPqcKemAlgorithm());
            response.setHeader("X-PQC-Classical",    session.getClassicalAlgorithm());

        } catch (Exception e) {
            log.warn("PQC handshake failed, falling back: {}", e.getMessage());
            response.setHeader("X-PQC-Mode",         "CLASSICAL");
            response.setHeader("X-PQC-Fallback",     "true");
            response.setHeader("X-PQC-Quantum-Safe", "false");
        }

        chain.doFilter(req, res);
    }

    private ClientCapability parseCapability(HttpServletRequest req) {
        String algoHeader    = req.getHeader(ClientCapability.HEADER_PQC_SUPPORTED);
        boolean pqcCapable   = algoHeader != null && !algoHeader.isBlank();
        boolean hybridCapable = "true".equalsIgnoreCase(req.getHeader(ClientCapability.HEADER_PQC_HYBRID));

        Set<String> algos = new HashSet<>();
        if (algoHeader != null) {
            Arrays.stream(algoHeader.split(",")).map(String::trim).forEach(algos::add);
        }

        int version = 0;
        try { version = Integer.parseInt(req.getHeader(ClientCapability.HEADER_PQC_VERSION)); }
        catch (Exception ignored) {}

        return ClientCapability.builder()
            .pqcCapable(pqcCapable)
            .hybridCapable(hybridCapable)
            .supportedAlgorithms(algos)
            .protocolVersion(version)
            .clientId(req.getRemoteAddr())
            .build();
    }
}
