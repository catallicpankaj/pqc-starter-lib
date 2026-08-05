package com.pqc.hybrid.keymanagement.providers;

import com.pqc.hybrid.keymanagement.api.KeyVersion;
import com.pqc.hybrid.keymanagement.api.WrappedKeyMaterial;
import com.pqc.hybrid.keymanagement.config.KeyManagementProperties;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.*;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

/**
 * Tests for {@link HashiCorpVaultKeyProvider} — a fully-implemented, non-stub production
 * KMS integration that made real HTTP calls with zero prior test coverage. Uses
 * {@link MockRestServiceServer} to stub Vault's Transit and KV v2 HTTP APIs precisely,
 * so these tests exercise the actual request/response wiring without a running Vault.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class HashiCorpVaultKeyProviderTest {

    private static final String VAULT_URI = "http://localhost:8200";

    private RestTemplate            rest;
    private MockRestServiceServer   server;
    private HashiCorpVaultKeyProvider provider;
    private KeyManagementProperties.Vault config;

    @BeforeAll
    static void setupProviders() {
        if (Security.getProvider("BC") == null) Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    @BeforeEach
    void setup() {
        config = new KeyManagementProperties.Vault();
        config.setUri(VAULT_URI);
        config.setToken("test-token");
        // transitKeyName / kvMountPath / kvKeyPath use their defaults

        rest     = new RestTemplate();
        server   = MockRestServiceServer.bindTo(rest).build();
        provider = new HashiCorpVaultKeyProvider(config, rest);
    }

    @Test @Order(1)
    @DisplayName("providerName() returns 'hashicorp-vault'")
    void providerNameIsCorrect() {
        assertThat(provider.providerName()).isEqualTo("hashicorp-vault");
    }

    @Test @Order(2)
    @DisplayName("wrapKey(): POSTs to transit/encrypt and extracts ciphertext + parsed version")
    void wrapKeyCallsTransitEncrypt() throws Exception {
        server.expect(requestTo(VAULT_URI + "/v1/transit/encrypt/pqc-starter-lib-master"))
              .andExpect(method(HttpMethod.POST))
              .andExpect(header("X-Vault-Token", "test-token"))
              .andRespond(withSuccess(
                  "{\"data\":{\"ciphertext\":\"vault:v3:abcdef1234567890\"}}",
                  MediaType.APPLICATION_JSON));

        WrappedKeyMaterial wrapped = provider.wrapKey("kyber-server-key", new byte[]{1, 2, 3, 4});

        assertThat(wrapped.keyId()).isEqualTo("kyber-server-key");
        assertThat(wrapped.version()).isEqualTo(3); // parsed from "vault:v3:..."
        assertThat(wrapped.context()).isEqualTo("vault:v3:abcdef1234567890");
        assertThat(wrapped.algorithm()).isEqualTo("vault-transit-aes256-gcm96");
        assertThat(wrapped.providerName()).isEqualTo("hashicorp-vault");
        server.verify();
        System.out.println("✓ wrapKey(): correct URL, headers, and response parsing");
    }

    @Test @Order(3)
    @DisplayName("unwrapKey(): POSTs the stored ciphertext to transit/decrypt and recovers raw bytes")
    void unwrapKeyCallsTransitDecrypt() throws Exception {
        byte[] originalKey = {10, 20, 30, 40, 50};
        String plaintextB64 = Base64.getEncoder().encodeToString(originalKey);

        server.expect(requestTo(VAULT_URI + "/v1/transit/decrypt/pqc-starter-lib-master"))
              .andExpect(method(HttpMethod.POST))
              .andExpect(jsonPath("$.ciphertext").value("vault:v1:xyz"))
              .andRespond(withSuccess(
                  "{\"data\":{\"plaintext\":\"" + plaintextB64 + "\"}}",
                  MediaType.APPLICATION_JSON));

        WrappedKeyMaterial wrapped = WrappedKeyMaterial.of(
            "kyber-server-key", 1, "vault:v1:xyz".getBytes(),
            "vault-transit-aes256-gcm96", "hashicorp-vault", "vault:v1:xyz");

        byte[] recovered = provider.unwrapKey("kyber-server-key", wrapped);

        assertThat(recovered).isEqualTo(originalKey);
        server.verify();
        System.out.println("✓ unwrapKey(): posts stored ciphertext, recovers original bytes");
    }

    @Test @Order(4)
    @DisplayName("storeKeyVersion(): PUTs full key metadata to the KV v2 data path")
    void storeKeyVersionCallsKvPut() throws Exception {
        KeyPair ecPair = generateEcKeyPair();
        KeyVersion kv = KeyVersion.builder()
            .keyId("ec-server-key").version(2)
            .algorithm(KeyVersion.KeyAlgorithm.EC_P384)
            .publicKey(ecPair.getPublic())
            .wrappedPrivateKey(WrappedKeyMaterial.of(
                "ec-server-key", 2, new byte[]{1}, "vault-transit-aes256-gcm96",
                "hashicorp-vault", "vault:v2:ciphertext"))
            .status(KeyVersion.Status.ACTIVE)
            .build();

        server.expect(requestTo(VAULT_URI + "/v1/secret/data/pqc-starter-lib/keys/ec-server-key/v2"))
              .andExpect(method(HttpMethod.PUT))
              .andExpect(jsonPath("$.data.keyId").value("ec-server-key"))
              .andExpect(jsonPath("$.data.status").value("ACTIVE"))
              .andRespond(withSuccess("{}", MediaType.APPLICATION_JSON));

        provider.storeKeyVersion(kv); // must not throw
        server.verify();
        System.out.println("✓ storeKeyVersion(): correct KV v2 PUT URL and payload shape");
    }

    @Test @Order(5)
    @DisplayName("loadKeyVersion(): GETs the KV v2 path and reconstructs a full KeyVersion")
    void loadKeyVersionReconstructsKeyVersion() throws Exception {
        KeyPair ecPair = generateEcKeyPair();
        String pubKeyB64 = Base64.getEncoder().encodeToString(ecPair.getPublic().getEncoded());

        String body = "{\"data\":{\"data\":{"
            + "\"keyId\":\"ec-server-key\","
            + "\"version\":\"1\","
            + "\"algorithm\":\"EC_P384\","
            + "\"status\":\"ACTIVE\","
            + "\"createdAt\":\"2026-01-01T00:00:00Z\","
            + "\"vaultCiphertext\":\"vault:v1:xyz\","
            + "\"wrappedAt\":\"2026-01-01T00:00:00Z\","
            + "\"publicKey\":\"" + pubKeyB64 + "\""
            + "}}}";

        server.expect(requestTo(VAULT_URI + "/v1/secret/data/pqc-starter-lib/keys/ec-server-key/v1"))
              .andExpect(method(HttpMethod.GET))
              .andRespond(withSuccess(body, MediaType.APPLICATION_JSON));

        Optional<KeyVersion> loaded = provider.loadKeyVersion("ec-server-key", 1);

        assertThat(loaded).isPresent();
        assertThat(loaded.get().getKeyId()).isEqualTo("ec-server-key");
        assertThat(loaded.get().getVersion()).isEqualTo(1);
        assertThat(loaded.get().getStatus()).isEqualTo(KeyVersion.Status.ACTIVE);
        assertThat(loaded.get().getPublicKey().getEncoded()).isEqualTo(ecPair.getPublic().getEncoded());
        server.verify();
        System.out.println("✓ loadKeyVersion(): reconstructs KeyVersion including public key from KV v2 response");
    }

    @Test @Order(6)
    @DisplayName("loadKeyVersion(): returns Optional.empty() on 404 (first startup — key not yet stored)")
    void loadKeyVersionReturnsEmptyOn404() throws Exception {
        server.expect(requestTo(VAULT_URI + "/v1/secret/data/pqc-starter-lib/keys/kyber-server-key/v1"))
              .andExpect(method(HttpMethod.GET))
              .andRespond(withStatus(org.springframework.http.HttpStatus.NOT_FOUND));

        Optional<KeyVersion> loaded = provider.loadKeyVersion("kyber-server-key", 1);

        assertThat(loaded).isEmpty();
        server.verify();
        System.out.println("✓ loadKeyVersion(): 404 -> Optional.empty(), not an exception");
    }

    @Test @Order(7)
    @DisplayName("listKeyVersions(): parses Vault's LIST metadata response into version numbers")
    void listKeyVersionsParsesVersionNumbers() throws Exception {
        server.expect(requestTo(VAULT_URI + "/v1/secret/metadata/pqc-starter-lib/keys/kyber-server-key"))
              .andExpect(method(HttpMethod.valueOf("LIST")))
              .andRespond(withSuccess(
                  "{\"data\":{\"keys\":[\"v1/\",\"v2/\",\"v3/\"]}}",
                  MediaType.APPLICATION_JSON));

        List<Integer> versions = provider.listKeyVersions("kyber-server-key");

        assertThat(versions).containsExactly(1, 2, 3);
        server.verify();
        System.out.println("✓ listKeyVersions(): parsed [v1/, v2/, v3/] -> [1, 2, 3]");
    }

    @Test @Order(8)
    @DisplayName("listKeyVersions(): returns an empty list on 404 (key never generated)")
    void listKeyVersionsReturnsEmptyOn404() throws Exception {
        server.expect(requestTo(VAULT_URI + "/v1/secret/metadata/pqc-starter-lib/keys/never-created"))
              .andExpect(method(HttpMethod.valueOf("LIST")))
              .andRespond(withStatus(org.springframework.http.HttpStatus.NOT_FOUND));

        List<Integer> versions = provider.listKeyVersions("never-created");

        assertThat(versions).isEmpty();
        server.verify();
        System.out.println("✓ listKeyVersions(): 404 -> empty list, not an exception");
    }

    @Test @Order(9)
    @DisplayName("isHealthy(): true when Vault reports initialized=true")
    void isHealthyTrueWhenVaultInitialized() {
        server.expect(requestTo(VAULT_URI + "/v1/sys/health"))
              .andExpect(method(HttpMethod.GET))
              .andRespond(withSuccess("{\"initialized\":true}", MediaType.APPLICATION_JSON));

        assertThat(provider.isHealthy()).isTrue();
        server.verify();
        System.out.println("✓ isHealthy(): true when Vault reports initialized=true");
    }

    @Test @Order(10)
    @DisplayName("isHealthy(): false when Vault reports initialized=false")
    void isHealthyFalseWhenVaultNotInitialized() {
        server.expect(requestTo(VAULT_URI + "/v1/sys/health"))
              .andRespond(withSuccess("{\"initialized\":false}", MediaType.APPLICATION_JSON));

        assertThat(provider.isHealthy()).isFalse();
        server.verify();
        System.out.println("✓ isHealthy(): false when Vault reports initialized=false");
    }

    @Test @Order(11)
    @DisplayName("isHealthy(): false (not an exception) when Vault is unreachable")
    void isHealthyFalseWhenVaultUnreachable() {
        server.expect(requestTo(VAULT_URI + "/v1/sys/health"))
              .andRespond(withServerError());

        assertThat(provider.isHealthy()).isFalse();
        server.verify();
        System.out.println("✓ isHealthy(): server error -> false, exception swallowed not propagated");
    }

    private KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(new ECGenParameterSpec("secp384r1"));
        return kpg.generateKeyPair();
    }
}
