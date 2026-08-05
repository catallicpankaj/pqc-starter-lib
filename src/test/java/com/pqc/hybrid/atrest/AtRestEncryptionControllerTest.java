package com.pqc.hybrid.atrest;

import com.pqc.hybrid.atrest.config.AtRestEncryptionProperties;
import com.pqc.hybrid.crypto.AesGcmEngine;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.*;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

/**
 * Tests for {@link AtRestEncryptionController} at the HTTP layer, using real collaborators
 * via MockMvcBuilders.standaloneSetup(). status() is fully-qualified throughout because
 * this controller has its own status() method in the same package, which shadows the
 * MockMvcResultMatchers.status() static import if wildcard-imported here.
 */
class AtRestEncryptionControllerTest {

    private static MockMvc mockMvc;

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BC") == null) Security.insertProviderAt(new BouncyCastleProvider(), 1);

        byte[] masterKey = new byte[32];
        new SecureRandom().nextBytes(masterKey);
        HkdfKeyDerivation hkdf = new HkdfKeyDerivation();
        EncryptedFieldService fieldService = new EncryptedFieldService(new AesGcmEngine(), hkdf, masterKey, 1);
        StreamingAesGcmEngine streamEngine = new StreamingAesGcmEngine();
        ReEncryptionService reEncService = new ReEncryptionService(fieldService);
        AtRestEncryptionService atRestService =
            new AtRestEncryptionService(fieldService, streamEngine, reEncService);

        AtRestEncryptionProperties props = new AtRestEncryptionProperties();
        props.setChunkSize(4096);

        AtRestEncryptionController controller = new AtRestEncryptionController(atRestService, props);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    @DisplayName("POST /api/atrest/encrypt-field then /decrypt-field -> round-trips the plaintext")
    void encryptThenDecryptField() throws Exception {
        String encryptRequest = "{\"plaintext\":\"123-45-6789\",\"recordId\":\"mvc-patient\",\"fieldName\":\"ssn\"}";

        String encryptResponse = mockMvc.perform(MockMvcRequestBuilders.post("/api/atrest/encrypt-field")
                .contentType(MediaType.APPLICATION_JSON)
                .content(encryptRequest))
            .andExpect(MockMvcResultMatchers.status().isOk())
            .andExpect(jsonPath("$.keyVersion").value(1))
            .andReturn().getResponse().getContentAsString();

        String encoded = extractJsonField(encryptResponse, "encoded");

        String decryptRequest = "{\"encoded\":\"" + encoded + "\",\"recordId\":\"mvc-patient\",\"fieldName\":\"ssn\"}";
        mockMvc.perform(MockMvcRequestBuilders.post("/api/atrest/decrypt-field")
                .contentType(MediaType.APPLICATION_JSON)
                .content(decryptRequest))
            .andExpect(MockMvcResultMatchers.status().isOk())
            .andExpect(jsonPath("$.plaintext").value("123-45-6789"));
    }

    @Test
    @DisplayName("POST /api/atrest/reencrypt-field -> already at current version, no-op (unchanged)")
    void reencryptFieldNoOpAtCurrentVersion() throws Exception {
        String encryptResponse = mockMvc.perform(MockMvcRequestBuilders.post("/api/atrest/encrypt-field")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"plaintext\":\"data\",\"recordId\":\"r1\",\"fieldName\":\"f1\"}"))
            .andReturn().getResponse().getContentAsString();
        String encoded = extractJsonField(encryptResponse, "encoded");

        mockMvc.perform(MockMvcRequestBuilders.post("/api/atrest/reencrypt-field")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"encoded\":\"" + encoded + "\",\"recordId\":\"r1\",\"fieldName\":\"f1\"}"))
            .andExpect(MockMvcResultMatchers.status().isOk())
            .andExpect(jsonPath("$.rekeyed").value(false));
    }

    @Test
    @DisplayName("POST /api/atrest/encrypt-bytes then /decrypt-bytes -> round-trips raw bytes")
    void encryptThenDecryptBytes() throws Exception {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        String keyB64 = Base64.getEncoder().encodeToString(key);
        String dataB64 = Base64.getEncoder().encodeToString("raw file bytes".getBytes());

        String encryptResponse = mockMvc.perform(MockMvcRequestBuilders.post("/api/atrest/encrypt-bytes")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"keyBase64\":\"" + keyB64 + "\",\"dataBase64\":\"" + dataB64 + "\"}"))
            .andExpect(MockMvcResultMatchers.status().isOk())
            .andReturn().getResponse().getContentAsString();
        String encryptedB64 = extractJsonField(encryptResponse, "encryptedBase64");

        String decryptResponse = mockMvc.perform(MockMvcRequestBuilders.post("/api/atrest/decrypt-bytes")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"keyBase64\":\"" + keyB64 + "\",\"encryptedBase64\":\"" + encryptedB64 + "\"}"))
            .andExpect(MockMvcResultMatchers.status().isOk())
            .andReturn().getResponse().getContentAsString();
        String recoveredB64 = extractJsonField(decryptResponse, "dataBase64");

        org.assertj.core.api.Assertions.assertThat(new String(Base64.getDecoder().decode(recoveredB64)))
            .isEqualTo("raw file bytes");
    }

    @Test
    @DisplayName("GET /api/atrest/status -> reports master key version and chunk size")
    void status() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/api/atrest/status"))
            .andExpect(MockMvcResultMatchers.status().isOk())
            .andExpect(jsonPath("$.masterKeyVersion").value(1))
            .andExpect(jsonPath("$.chunkSize").value(4096))
            .andExpect(jsonPath("$.phase").value("Phase 6 — Data at Rest"));
    }

    private static String extractJsonField(String json, String field) {
        String marker = "\"" + field + "\":\"";
        int start = json.indexOf(marker) + marker.length();
        int end = json.indexOf('"', start);
        return json.substring(start, end);
    }
}
