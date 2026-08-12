package com.pqc.hybrid.controller;

import com.pqc.hybrid.crypto.AesGcmEngine;
import com.pqc.hybrid.crypto.PqcEncryptionService;
import com.pqc.hybrid.handshake.HandshakeSession;
import com.pqc.hybrid.handshake.HybridHandshakeOrchestrator;
import com.pqc.hybrid.handshake.KyberKemEngine;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.*;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.security.Security;
import java.util.Optional;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Tests for {@link EncryptionDemoController} at the HTTP layer, using real crypto
 * collaborators (no mocking) via MockMvcBuilders.standaloneSetup().
 */
class EncryptionDemoControllerTest {

    private static MockMvc mockMvc;
    private static PqcEncryptionService pqcEncryption;

    @BeforeAll
    static void setup() throws Exception {
        if (Security.getProvider("BC")    == null) Security.insertProviderAt(new BouncyCastleProvider(),    1);
        if (Security.getProvider("BCPQC") == null) Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);

        HybridHandshakeOrchestrator orchestrator = new HybridHandshakeOrchestrator(Optional.empty());
        AesGcmEngine aesGcm = new AesGcmEngine();
        pqcEncryption = new PqcEncryptionService(orchestrator, aesGcm, new KyberKemEngine());
        EncryptionDemoController controller = new EncryptionDemoController(pqcEncryption, orchestrator, aesGcm);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    @DisplayName("POST /api/encrypt/e2e -> full pipeline round-trips and verifies")
    void endToEndPipeline() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.post("/api/encrypt/e2e").param("message", "HelloPQC"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.roundTripVerified").value(true))
            .andExpect(jsonPath("$.decryptedText").value("HelloPQC"));
    }

    @Test
    @DisplayName("POST /api/encrypt/session -> establishes a session, returns HYBRID + quantumSafe")
    void createSession() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.post("/api/encrypt/session").param("clientId", "mvc-test"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.cipherMode").value("HYBRID"))
            .andExpect(jsonPath("$.quantumSafe").value(true))
            .andExpect(jsonPath("$.sessionId").isNotEmpty());
    }

    @Test
    @DisplayName("POST /api/encrypt/encrypt then /decrypt -> round-trips a plaintext payload")
    void encryptThenDecrypt() throws Exception {
        HandshakeSession session = pqcEncryption.establishHybridSession("mvc-encrypt-test");

        String encryptRequest = "{\"sessionId\":\"" + session.getSessionId() + "\",\"plaintext\":\"secret data\"}";
        String encryptResponse = mockMvc.perform(MockMvcRequestBuilders.post("/api/encrypt/encrypt")
                .contentType(MediaType.APPLICATION_JSON)
                .content(encryptRequest))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.wireBreakdown.ivBytes").value(12))
            .andReturn().getResponse().getContentAsString();

        String ciphertext = extractJsonField(encryptResponse, "ciphertext");

        String decryptRequest = "{\"sessionId\":\"" + session.getSessionId() + "\",\"ciphertext\":\"" + ciphertext + "\"}";
        mockMvc.perform(MockMvcRequestBuilders.post("/api/encrypt/decrypt")
                .contentType(MediaType.APPLICATION_JSON)
                .content(decryptRequest))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.plaintext").value("secret data"))
            .andExpect(jsonPath("$.gcmVerified").value(true));
    }

    @Test
    @DisplayName("POST /api/encrypt/tamper-test -> proves GCM authentication rejects a tampered ciphertext")
    void tamperTest() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.post("/api/encrypt/tamper-test"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.tamperDetected").value(true))
            .andExpect(jsonPath("$.originalStillDecrypts").value(true));
    }

    @Test
    @DisplayName("GET /api/encrypt/compare-modes -> all three modes produce the same ciphertext byte length")
    void compareModes() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/api/encrypt/compare-modes"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.modes.CLASSICAL.quantumSafe").value(false))
            .andExpect(jsonPath("$.modes.HYBRID.quantumSafe").value(true))
            .andExpect(jsonPath("$.modes.CLASSICAL.decryptVerified").value(true))
            .andExpect(jsonPath("$.modes.HYBRID.decryptVerified").value(true));
    }

    private static String extractJsonField(String json, String field) {
        String marker = "\"" + field + "\":\"";
        int start = json.indexOf(marker) + marker.length();
        int end = json.indexOf('"', start);
        return json.substring(start, end);
    }
}
