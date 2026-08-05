package com.pqc.hybrid.migration;

import com.pqc.hybrid.handshake.HybridHandshakeOrchestrator;
import com.pqc.hybrid.migration.config.RsaMigrationProperties;
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
 * Tests for {@link RsaMigrationController} at the HTTP layer, using real collaborators
 * via MockMvcBuilders.standaloneSetup() — including /rsa-public-key, which no other
 * test in the suite exercises at all.
 */
class RsaMigrationControllerTest {

    private static MockMvc mockMvc;

    @BeforeAll
    static void setup() throws Exception {
        if (Security.getProvider("BC")    == null) Security.insertProviderAt(new BouncyCastleProvider(),    1);
        if (Security.getProvider("BCPQC") == null) Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);

        RsaKeyConverter rsaConverter = new RsaKeyConverter();
        HybridHandshakeOrchestrator orchestrator = new HybridHandshakeOrchestrator(Optional.empty());
        RsaMigrationProperties props = new RsaMigrationProperties();
        props.setDefaultMode(MigrationMode.BRIDGE);
        props.setRolloutPercentage(100); // deterministic: always PQC for this test class

        RsaKyberBridgeService bridgeService = new RsaKyberBridgeService(rsaConverter, orchestrator, props);
        RsaMigrationController controller = new RsaMigrationController(bridgeService, props);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    @DisplayName("POST /api/migration/bridge-handshake -> rollout=100% always routes to PQC/HYBRID")
    void bridgeHandshake() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.post("/api/migration/bridge-handshake").param("clientId", "svc-a"))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
            .andExpect(jsonPath("$.negotiatedCipherMode").value("HYBRID"))
            .andExpect(jsonPath("$.quantumSafe").value(true));
    }

    @Test
    @DisplayName("POST /api/migration/simulate-legacy -> always CLASSICAL/RSA regardless of rollout %")
    void simulateLegacy() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.post("/api/migration/simulate-legacy").param("clientId", "legacy-a"))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
            .andExpect(jsonPath("$.negotiatedCipherMode").value("CLASSICAL"))
            .andExpect(jsonPath("$.quantumSafe").value(false))
            .andExpect(jsonPath("$.classicalAlgorithm").value("RSA-2048-OAEP"));
    }

    @Test
    @DisplayName("POST /api/migration/simulate-pqc -> always HYBRID/quantum-safe")
    void simulatePqc() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.post("/api/migration/simulate-pqc").param("clientId", "modern-a"))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
            .andExpect(jsonPath("$.negotiatedCipherMode").value("HYBRID"))
            .andExpect(jsonPath("$.quantumSafe").value(true));
    }

    @Test
    @DisplayName("GET /api/migration/status -> reflects sessions established by prior requests")
    void status() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.post("/api/migration/simulate-legacy").param("clientId", "status-legacy"));
        mockMvc.perform(MockMvcRequestBuilders.post("/api/migration/simulate-pqc").param("clientId", "status-pqc"));

        mockMvc.perform(MockMvcRequestBuilders.get("/api/migration/status"))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
            .andExpect(jsonPath("$.rsaSessions").isNumber())
            .andExpect(jsonPath("$.pqcOnlySessions").isNumber())
            .andExpect(jsonPath("$.totalSessions").isNumber());
    }

    @Test
    @DisplayName("GET /api/migration/rsa-public-key -> reports RSA-2048 metadata, no private key exposed")
    void rsaPublicKey() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/api/migration/rsa-public-key"))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
            .andExpect(jsonPath("$.algorithm").value("RSA-2048"))
            .andExpect(jsonPath("$.format").value("X.509 SubjectPublicKeyInfo"))
            .andExpect(jsonPath("$.encodedLength").exists());
    }
}
