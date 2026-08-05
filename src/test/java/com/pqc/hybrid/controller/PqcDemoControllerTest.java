package com.pqc.hybrid.controller;

import com.pqc.hybrid.filter.HybridHandshakeFilter;
import com.pqc.hybrid.handshake.HandshakeSession;
import com.pqc.hybrid.handshake.HybridHandshakeOrchestrator;
import com.pqc.hybrid.signing.DilithiumSigningEngine;
import com.pqc.hybrid.signing.SphincsSigningEngine;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.*;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.security.Security;
import java.util.Optional;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Tests for {@link PqcDemoController} at the HTTP layer — request/response mapping,
 * not the underlying crypto (already covered by the engine-level tests). Uses
 * MockMvcBuilders.standaloneSetup() with real collaborators rather than @WebMvcTest,
 * to avoid pulling in a full Spring context or a mocking framework for a single controller.
 */
class PqcDemoControllerTest {

    private static MockMvc mockMvc;
    private static HybridHandshakeOrchestrator orchestrator;

    @BeforeAll
    static void setup() throws Exception {
        if (Security.getProvider("BC")    == null) Security.insertProviderAt(new BouncyCastleProvider(),    1);
        if (Security.getProvider("BCPQC") == null) Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);

        orchestrator = new HybridHandshakeOrchestrator(Optional.empty());
        PqcDemoController controller = new PqcDemoController(
            orchestrator, new DilithiumSigningEngine(), new SphincsSigningEngine());
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    @DisplayName("GET /api/pqc/status without a handshake request attribute -> 'filter-not-active'")
    void statusWithoutFilterAttribute() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/api/pqc/status"))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
            .andExpect(jsonPath("$.status").value("filter-not-active"));
    }

    @Test
    @DisplayName("GET /api/pqc/status with a handshake session attribute set -> reports the negotiated mode")
    void statusWithFilterAttribute() throws Exception {
        HandshakeSession session = orchestrator.orchestrate(
            com.pqc.hybrid.handshake.ClientCapability.builder()
                .pqcCapable(true).hybridCapable(true)
                .supportedAlgorithms(java.util.Set.of("Kyber-768")).clientId("mockmvc-test").build());

        mockMvc.perform(MockMvcRequestBuilders.get("/api/pqc/status")
                .requestAttr(HybridHandshakeFilter.ATTR_SESSION, session))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
            .andExpect(jsonPath("$.cipherMode").value("HYBRID"))
            .andExpect(jsonPath("$.quantumSafe").value(true));
    }

    @Test
    @DisplayName("GET /api/pqc/upgrade-demo -> reports a CLASSICAL -> HYBRID upgrade")
    void upgradeDemo() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/api/pqc/upgrade-demo"))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
            .andExpect(jsonPath("$.upgraded").value(true))
            .andExpect(jsonPath("$.before.cipherMode").value("CLASSICAL"))
            .andExpect(jsonPath("$.after.cipherMode").value("HYBRID"));
    }

    @Test
    @DisplayName("POST /api/pqc/sign -> real Dilithium-3 signature, verified=true")
    void signWithDilithium() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.post("/api/pqc/sign").param("message", "hello"))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
            .andExpect(jsonPath("$.algorithm").value("Dilithium-3 (ML-DSA-65)"))
            .andExpect(jsonPath("$.verified").value(true))
            .andExpect(jsonPath("$.signatureBytes").isNumber());
    }

    @Test
    @DisplayName("POST /api/pqc/sign-sphincs -> real SPHINCS+ signature, verified=true")
    void signWithSphincs() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.post("/api/pqc/sign-sphincs").param("message", "hello"))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
            .andExpect(jsonPath("$.algorithm").value("SPHINCS+-SHA2-128f (SLH-DSA)"))
            .andExpect(jsonPath("$.verified").value(true));
    }

    @Test
    @DisplayName("POST /api/pqc/sign without a message param uses the default 'Hello PQC'")
    void signWithDefaultMessage() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.post("/api/pqc/sign"))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
            .andExpect(jsonPath("$.message").value("Hello PQC"))
            .andExpect(jsonPath("$.verified").value(true));
    }
}
