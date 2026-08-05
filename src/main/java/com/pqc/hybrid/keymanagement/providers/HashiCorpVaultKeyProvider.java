package com.pqc.hybrid.keymanagement.providers;

import com.pqc.hybrid.keymanagement.api.KeyManagementProvider;
import com.pqc.hybrid.keymanagement.api.KeyVersion;
import com.pqc.hybrid.keymanagement.api.WrappedKeyMaterial;
import com.pqc.hybrid.keymanagement.config.KeyManagementProperties;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.*;

/**
 * ═══════════════════════════════════════════════════════════════════════
 * HASHICORP VAULT KEY PROVIDER
 * Wraps / unwraps private keys using Vault Transit Secrets Engine.
 * Persists versioned key metadata in Vault KV v2 Secrets Engine.
 * ═══════════════════════════════════════════════════════════════════════
 *
 * VAULT ENGINES USED:
 *
 *   Transit Secrets Engine (/v1/transit/...)
 *   ─────────────────────────────────────────
 *   Vault performs AES-256-GCM wrapping internally.
 *   The master key NEVER leaves the Vault boundary — the application
 *   sends raw key bytes and receives back an opaque ciphertext string.
 *
 *   KV v2 Secrets Engine (/v1/{mount}/...)
 *   ─────────────────────────────────────
 *   Stores versioned key metadata (ciphertext, public key, algorithm, status)
 *   so the application can reconstruct KeyPair objects on restart.
 *
 * ONE-TIME VAULT SETUP:
 *   vault secrets enable transit
 *   vault write -f transit/keys/pqc-starter-lib-master
 *   vault secrets enable -path=secret kv-v2   # (pre-enabled in dev server)
 *
 * ACTIVATE WITH:
 *   pqc.key-management.provider=hashicorp-vault
 *   pqc.key-management.vault.uri=http://localhost:8200
 *   pqc.key-management.vault.token=<your-token>
 *   pqc.key-management.vault.transit-key-name=pqc-starter-lib-master
 *
 * VAULT API CALLS:
 *   wrapKey   → POST /v1/transit/encrypt/{transitKeyName}
 *               body: {"plaintext": "<base64(rawBytes)>"}
 *               returns: {"data": {"ciphertext": "vault:v1:..."}}
 *
 *   unwrapKey → POST /v1/transit/decrypt/{transitKeyName}
 *               body: {"ciphertext": "vault:v1:..."}
 *               returns: {"data": {"plaintext": "<base64(rawBytes)>"}}
 *
 *   store     → PUT  /v1/{kvMount}/data/{kvKeyPath}/{keyId}/v{version}
 *   load      → GET  /v1/{kvMount}/data/{kvKeyPath}/{keyId}/v{version}
 *   list      → LIST /v1/{kvMount}/metadata/{kvKeyPath}/{keyId}
 */
public class HashiCorpVaultKeyProvider implements KeyManagementProvider {

    private static final Logger log = LoggerFactory.getLogger(HashiCorpVaultKeyProvider.class);
    private static final String PROVIDER_NAME = "hashicorp-vault";

    private static final ParameterizedTypeReference<Map<String, Object>> MAP_TYPE =
        new ParameterizedTypeReference<>() {};

    private final KeyManagementProperties.Vault config;
    private final RestTemplate rest;

    static {
        if (Security.getProvider("BC")    == null) Security.insertProviderAt(new BouncyCastleProvider(),    1);
        if (Security.getProvider("BCPQC") == null) Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);
    }

    public HashiCorpVaultKeyProvider(KeyManagementProperties.Vault config) {
        this(config, new RestTemplate());
    }

    /** Package-private — lets tests bind a {@code MockRestServiceServer} without a real Vault instance. */
    HashiCorpVaultKeyProvider(KeyManagementProperties.Vault config, RestTemplate rest) {
        this.config = config;
        this.rest   = rest;
    }

    // ─────────────────────────────────────────────────────────────
    // Wrap / Unwrap — Vault Transit Secrets Engine
    // ─────────────────────────────────────────────────────────────

    /**
     * Wraps a raw private key using Vault's Transit Secrets Engine.
     *
     * POST /v1/transit/encrypt/{transitKeyName}
     *   X-Vault-Token: {token}
     *   body: {"plaintext": "<base64(rawPrivateKey)>"}
     *
     * The "vault:v{N}:..." ciphertext returned by Vault is stored in
     * WrappedKeyMaterial.context — it is required for the decrypt endpoint.
     */
    @Override
    @SuppressWarnings("unchecked")
    public WrappedKeyMaterial wrapKey(String keyId, byte[] rawPrivateKey) throws Exception {
        String plainTextB64 = Base64.getEncoder().encodeToString(rawPrivateKey);

        Map<String, String> body = Map.of("plaintext", plainTextB64);
        ResponseEntity<Map<String, Object>> response = rest.exchange(
            transitUrl("/encrypt/" + config.getTransitKeyName()),
            HttpMethod.POST,
            new HttpEntity<>(body, vaultHeaders()),
            MAP_TYPE
        );

        Map<String, Object> data = (Map<String, Object>)
            Objects.requireNonNull(response.getBody()).get("data");
        String ciphertext = (String) data.get("ciphertext"); // "vault:v1:..."

        log.info("[vault] wrapKey: keyId={} ciphertext-prefix={}",
            keyId, ciphertext.substring(0, Math.min(20, ciphertext.length())));

        return WrappedKeyMaterial.of(
            keyId,
            parseVaultVersion(ciphertext),
            ciphertext.getBytes(),
            "vault-transit-aes256-gcm96",
            PROVIDER_NAME,
            ciphertext  // context = full ciphertext string needed for the decrypt call
        );
    }

    /**
     * Unwraps a private key using Vault's Transit Secrets Engine.
     *
     * POST /v1/transit/decrypt/{transitKeyName}
     *   X-Vault-Token: {token}
     *   body: {"ciphertext": "vault:v1:..."}
     */
    @Override
    @SuppressWarnings("unchecked")
    public byte[] unwrapKey(String keyId, WrappedKeyMaterial wrapped) throws Exception {
        String ciphertext = wrapped.context(); // stored during wrapKey()

        Map<String, String> body = Map.of("ciphertext", ciphertext);
        ResponseEntity<Map<String, Object>> response = rest.exchange(
            transitUrl("/decrypt/" + config.getTransitKeyName()),
            HttpMethod.POST,
            new HttpEntity<>(body, vaultHeaders()),
            MAP_TYPE
        );

        Map<String, Object> data = (Map<String, Object>)
            Objects.requireNonNull(response.getBody()).get("data");
        String plaintextB64 = (String) data.get("plaintext");

        byte[] rawKey = Base64.getDecoder().decode(plaintextB64);
        log.debug("[vault] unwrapKey: keyId={} recovered={}B", keyId, rawKey.length);
        return rawKey;
    }

    // ─────────────────────────────────────────────────────────────
    // Persistence — Vault KV v2 Secrets Engine
    // ─────────────────────────────────────────────────────────────

    /**
     * Stores a key version in Vault KV v2.
     *
     * PUT /v1/{kvMount}/data/{kvKeyPath}/{keyId}/v{version}
     */
    @Override
    public void storeKeyVersion(KeyVersion kv) throws Exception {
        Map<String, String> kvData = new LinkedHashMap<>();
        kvData.put("keyId",           kv.getKeyId());
        kvData.put("version",         String.valueOf(kv.getVersion()));
        kvData.put("algorithm",       kv.getAlgorithm().name());
        kvData.put("status",          kv.getStatus().name());
        kvData.put("createdAt",       kv.getCreatedAt().toString());
        kvData.put("vaultCiphertext", kv.getWrappedPrivateKey().context());
        kvData.put("wrappedAt",       kv.getWrappedPrivateKey().wrappedAt().toString());
        kvData.put("publicKey",       Base64.getEncoder().encodeToString(kv.getPublicKey().getEncoded()));
        if (kv.getDeprecatedAt() != null) kvData.put("deprecatedAt", kv.getDeprecatedAt().toString());
        if (kv.getRetiredAt()    != null) kvData.put("retiredAt",    kv.getRetiredAt().toString());

        Map<String, Object> requestBody = Map.of("data", kvData);

        rest.exchange(
            kvDataUrl(kv.getKeyId(), kv.getVersion()),
            HttpMethod.PUT,
            new HttpEntity<>(requestBody, vaultHeaders()),
            MAP_TYPE
        );

        log.info("[vault] stored keyVersion: keyId={} version={} status={}",
            kv.getKeyId(), kv.getVersion(), kv.getStatus());
    }

    /**
     * Loads a key version from Vault KV v2.
     *
     * GET /v1/{kvMount}/data/{kvKeyPath}/{keyId}/v{version}
     */
    @Override
    @SuppressWarnings("unchecked")
    public Optional<KeyVersion> loadKeyVersion(String keyId, int version) throws Exception {
        try {
            ResponseEntity<Map<String, Object>> response = rest.exchange(
                kvDataUrl(keyId, version),
                HttpMethod.GET,
                new HttpEntity<>(vaultHeaders()),
                MAP_TYPE
            );

            Map<String, Object> outer = (Map<String, Object>)
                Objects.requireNonNull(response.getBody()).get("data");
            Map<String, String> d = (Map<String, String>) outer.get("data");

            String vaultCiphertext = d.get("vaultCiphertext");
            WrappedKeyMaterial wrapped = new WrappedKeyMaterial(
                keyId,
                Integer.parseInt(d.get("version")),
                vaultCiphertext.getBytes(),
                "vault-transit-aes256-gcm96",
                PROVIDER_NAME,
                vaultCiphertext,
                Instant.parse(d.get("wrappedAt"))
            );

            KeyVersion.KeyAlgorithm algo = KeyVersion.KeyAlgorithm.valueOf(d.get("algorithm"));
            byte[] pubKeyBytes = Base64.getDecoder().decode(d.get("publicKey"));
            PublicKey publicKey = rebuildPublicKey(algo, pubKeyBytes);

            KeyVersion.Builder builder = KeyVersion.builder()
                .keyId(keyId)
                .version(Integer.parseInt(d.get("version")))
                .algorithm(algo)
                .publicKey(publicKey)
                .wrappedPrivateKey(wrapped)
                .status(KeyVersion.Status.valueOf(d.get("status")));

            if (d.containsKey("deprecatedAt")) builder.deprecatedAt(Instant.parse(d.get("deprecatedAt")));
            if (d.containsKey("retiredAt"))    builder.retiredAt(Instant.parse(d.get("retiredAt")));

            log.info("[vault] loaded keyVersion: keyId={} version={}", keyId, version);
            return Optional.of(builder.build());

        } catch (HttpClientErrorException.NotFound e) {
            return Optional.empty(); // first startup — key not yet stored
        }
    }

    /**
     * Lists stored version numbers via Vault KV v2 metadata.
     *
     * LIST /v1/{kvMount}/metadata/{kvKeyPath}/{keyId}
     */
    @Override
    @SuppressWarnings("unchecked")
    public List<Integer> listKeyVersions(String keyId) throws Exception {
        try {
            ResponseEntity<Map<String, Object>> response = rest.exchange(
                kvMetadataUrl(keyId),
                HttpMethod.valueOf("LIST"),
                new HttpEntity<>(vaultHeaders()),
                MAP_TYPE
            );

            Map<String, Object> data = (Map<String, Object>)
                Objects.requireNonNull(response.getBody()).get("data");
            List<String> keys = (List<String>) data.get("keys");

            List<Integer> versions = new ArrayList<>();
            for (String key : keys) {
                try {
                    versions.add(Integer.parseInt(key.replace("v", "").replace("/", "")));
                } catch (NumberFormatException ignored) {}
            }
            Collections.sort(versions);
            return versions;

        } catch (HttpClientErrorException.NotFound e) {
            return List.of(); // no versions stored yet
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Health check
    // ─────────────────────────────────────────────────────────────

    @Override
    public boolean isHealthy() {
        try {
            ResponseEntity<Map<String, Object>> response = rest.exchange(
                config.getUri() + "/v1/sys/health",
                HttpMethod.GET,
                new HttpEntity<>(vaultHeaders()),
                MAP_TYPE
            );
            boolean initialized = Boolean.TRUE.equals(
                Objects.requireNonNull(response.getBody()).get("initialized"));
            log.debug("[vault] health check: initialized={} status={}", initialized, response.getStatusCode());
            return initialized;
        } catch (Exception e) {
            log.warn("[vault] health check failed: {}", e.getMessage());
            return false;
        }
    }

    @Override
    public String providerName() { return PROVIDER_NAME; }

    // ─────────────────────────────────────────────────────────────
    // Internal helpers
    // ─────────────────────────────────────────────────────────────

    private HttpHeaders vaultHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        if (config.getToken() != null) {
            headers.set("X-Vault-Token", config.getToken());
        }
        return headers;
    }

    private String transitUrl(String path) {
        return config.getUri() + "/v1/transit" + path;
    }

    private String kvDataUrl(String keyId, int version) {
        return config.getUri() + "/v1/" + config.getKvMountPath() +
               "/data/" + config.getKvKeyPath() + "/" + keyId + "/v" + version;
    }

    private String kvMetadataUrl(String keyId) {
        return config.getUri() + "/v1/" + config.getKvMountPath() +
               "/metadata/" + config.getKvKeyPath() + "/" + keyId;
    }

    /** Extracts the version number from a Vault ciphertext string "vault:v{N}:..." */
    private int parseVaultVersion(String ciphertext) {
        try {
            return Integer.parseInt(ciphertext.split(":")[1].substring(1)); // "v1" → 1
        } catch (Exception e) {
            return 1;
        }
    }

    private PublicKey rebuildPublicKey(KeyVersion.KeyAlgorithm algo, byte[] encoded) throws Exception {
        KeyFactory kf = KeyFactory.getInstance(algo.getBcAlgorithmName(), algo.getBcProviderName());
        return kf.generatePublic(new X509EncodedKeySpec(encoded));
    }
}
