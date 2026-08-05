package com.pqc.hybrid.keymanagement.api;

import java.util.List;
import java.util.Optional;

/**
 * ═══════════════════════════════════════════════════════════════════════
 * KEY MANAGEMENT PROVIDER — Strategy Interface
 * ═══════════════════════════════════════════════════════════════════════
 *
 * DESIGN PATTERN: Strategy (GoF)
 * ──────────────────────────────
 * This interface is the single extension point for all KMS / HSM providers.
 * Each implementation (Vault, AWS KMS, Azure Key Vault, GCP KMS, Local)
 * satisfies the same contract identically — the rest of the system never
 * knows which provider is active.
 *
 * ACTIVE PROVIDER IS SELECTED VIA:
 *   pqc.key-management.provider=hashicorp-vault   (or local / aws-kms / azure-key-vault / gcp-kms)
 *
 * TO ADD A NEW PROVIDER:
 *   1. Create a class implementing this interface
 *   2. Register it as a @Bean in KeyManagementAutoConfiguration with an appropriate
 *      @ConditionalOnProperty(name = "pqc.key-management.provider", havingValue = "your-name")
 *   3. Add provider-specific config fields to KeyManagementProperties
 *   4. No other code changes are required — QuantumKeyService and HybridHandshakeOrchestrator
 *      will pick up the new provider automatically.
 *
 * KEY CONCEPTS:
 *   wrapKey()   — encrypt a raw private key using the KMS master key.
 *                 The master key never leaves the KMS boundary.
 *                 The wrapped result is safe to store in a database or secret store.
 *   unwrapKey() — decrypt wrapped bytes back to the original raw private key.
 *   storeKeyVersion() / loadKeyVersion() — versioned key persistence (bootstrap + restart).
 *   isHealthy() — connectivity probe used by the /actuator/pqc endpoint.
 */
public interface KeyManagementProvider {

    /**
     * Wrap (encrypt) a raw private key using the KMS master key.
     *
     * The KMS master key never leaves the KMS boundary. The application sends
     * raw key bytes to the KMS and receives opaque wrapped bytes back. The wrapped
     * bytes can be stored safely in a database, file, or secret store.
     *
     * @param keyId         logical identifier for this key (e.g. "kyber-server-key")
     * @param rawPrivateKey DER-encoded private key bytes produced by BouncyCastle
     * @return WrappedKeyMaterial containing encrypted bytes + audit metadata
     */
    WrappedKeyMaterial wrapKey(String keyId, byte[] rawPrivateKey) throws Exception;

    /**
     * Unwrap (decrypt) a previously wrapped private key.
     *
     * @param keyId   same logical identifier used during wrapKey()
     * @param wrapped the WrappedKeyMaterial returned by a prior wrapKey() call
     * @return original raw DER-encoded private key bytes
     */
    byte[] unwrapKey(String keyId, WrappedKeyMaterial wrapped) throws Exception;

    /**
     * Persist a complete versioned key entry to the provider's durable storage.
     *
     * Called after key generation (bootstrap) and after rotation.
     * The stored entry includes the wrapped private key, public key bytes,
     * algorithm metadata, and version status — enough to fully reconstruct
     * a KeyPair after an application restart.
     *
     * Provider-specific storage targets:
     *   HashiCorp Vault  → Vault KV v2 secrets engine
     *   AWS KMS          → SSM Parameter Store or Secrets Manager
     *   Azure Key Vault  → Key Vault Secrets
     *   GCP KMS          → Secret Manager
     *   Local            → filesystem under ~/.pqc-starter-lib/keys/
     *
     * Default: no-op (providers that manage storage internally can skip this).
     */
    default void storeKeyVersion(KeyVersion keyVersion) throws Exception {}

    /**
     * Load a previously stored key version from the provider's durable storage.
     * Returns empty Optional if the key does not exist yet (first application startup).
     *
     * @param keyId   logical key identifier
     * @param version version number (1-based; use 0 to load the latest active version)
     * @return KeyVersion if found, empty Optional on first startup
     */
    default Optional<KeyVersion> loadKeyVersion(String keyId, int version) throws Exception {
        return Optional.empty();
    }

    /**
     * List all stored version numbers for a given key ID.
     * Used during startup to discover the current active version.
     *
     * @param keyId logical key identifier
     * @return sorted list of version numbers, empty if key has never been generated
     */
    default List<Integer> listKeyVersions(String keyId) throws Exception {
        return List.of();
    }

    /**
     * Probe connectivity and authentication to the KMS provider.
     *
     * Called at application startup and by the /actuator/pqc endpoint.
     * A false return will trigger fallback behaviour in QuantumKeyService.
     *
     * @return true if the provider is reachable and credentials are valid
     */
    boolean isHealthy();

    /**
     * Human-readable provider identifier.
     * Must match the value of pqc.key-management.provider in application.yml.
     * Used in logging, actuator output, and audit records.
     */
    String providerName();
}
