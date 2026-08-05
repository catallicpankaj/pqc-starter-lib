package com.pqc.hybrid.keymanagement.config;

import com.pqc.hybrid.keymanagement.api.KeyManagementProvider;
import com.pqc.hybrid.keymanagement.providers.*;
import com.pqc.hybrid.keymanagement.registry.KeyRegistry;
import com.pqc.hybrid.keymanagement.rotation.KeyRotationManager;
import com.pqc.hybrid.keymanagement.service.QuantumKeyService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * ═══════════════════════════════════════════════════════════════════════
 * KEY MANAGEMENT AUTO-CONFIGURATION
 * ═══════════════════════════════════════════════════════════════════════
 *
 * Activates ONLY when pqc.key-management.provider is set.
 * When absent, Phase 3 is disabled and the orchestrator uses ephemeral
 * in-memory keys (Phase 1/2 behaviour — no changes to existing functionality).
 *
 * PROVIDER SELECTION:
 *   The provider is selected by matching pqc.key-management.provider
 *   to one of the @ConditionalOnProperty values below. Only the matching
 *   @Bean method fires — all others are skipped.
 *
 *   provider=local            → LocalDevKeyProvider    (file-based, dev only)
 *   provider=hashicorp-vault  → HashiCorpVaultKeyProvider (Transit + KV v2)
 *   provider=aws-kms          → AwsKmsKeyProvider      (stub)
 *   provider=azure-key-vault  → AzureKeyVaultKeyProvider (stub)
 *   provider=gcp-kms          → GcpKmsKeyProvider      (stub)
 *
 * ADDING A NEW PROVIDER:
 *   1. Implement KeyManagementProvider
 *   2. Add a @Bean method below with the appropriate @ConditionalOnProperty
 *   3. Add config fields to KeyManagementProperties
 *   That's it — no other code changes needed.
 *
 * BEANS REGISTERED (when Phase 3 is active):
 *   KeyManagementProvider  — the selected provider implementation
 *   KeyRegistry            — in-memory versioned key store
 *   QuantumKeyService      — bootstraps keys at startup; provides active KeyPairs
 *   KeyRotationManager     — scheduled rotation (when rotation.enabled=true)
 *
 * HybridHandshakeOrchestrator will detect the QuantumKeyService bean and
 * automatically use KMS-managed persistent keys instead of ephemeral ones.
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "pqc.key-management", name = "provider")
@EnableConfigurationProperties(KeyManagementProperties.class)
@EnableScheduling
public class KeyManagementAutoConfiguration {

    // ─────────────────────────────────────────────────────────────
    // Provider selection — exactly ONE of these fires based on config
    // ─────────────────────────────────────────────────────────────

    @Bean
    @ConditionalOnMissingBean(KeyManagementProvider.class)
    @ConditionalOnProperty(name = "pqc.key-management.provider", havingValue = "local")
    KeyManagementProvider localDevKeyProvider(KeyManagementProperties props) {
        return new LocalDevKeyProvider(props.getLocal());
    }

    @Bean
    @ConditionalOnMissingBean(KeyManagementProvider.class)
    @ConditionalOnProperty(name = "pqc.key-management.provider", havingValue = "hashicorp-vault")
    KeyManagementProvider hashiCorpVaultKeyProvider(KeyManagementProperties props) {
        return new HashiCorpVaultKeyProvider(props.getVault());
    }

    @Bean
    @ConditionalOnMissingBean(KeyManagementProvider.class)
    @ConditionalOnProperty(name = "pqc.key-management.provider", havingValue = "aws-kms")
    KeyManagementProvider awsKmsKeyProvider(KeyManagementProperties props) {
        return new AwsKmsKeyProvider(props.getAws());
    }

    @Bean
    @ConditionalOnMissingBean(KeyManagementProvider.class)
    @ConditionalOnProperty(name = "pqc.key-management.provider", havingValue = "azure-key-vault")
    KeyManagementProvider azureKeyVaultKeyProvider(KeyManagementProperties props) {
        return new AzureKeyVaultKeyProvider(props.getAzure());
    }

    @Bean
    @ConditionalOnMissingBean(KeyManagementProvider.class)
    @ConditionalOnProperty(name = "pqc.key-management.provider", havingValue = "gcp-kms")
    KeyManagementProvider gcpKmsKeyProvider(KeyManagementProperties props) {
        return new GcpKmsKeyProvider(props.getGcp());
    }

    // ─────────────────────────────────────────────────────────────
    // Registry, Service, Rotation — always created when Phase 3 is active
    // ─────────────────────────────────────────────────────────────

    @Bean
    @ConditionalOnMissingBean
    KeyRegistry keyRegistry() {
        return new KeyRegistry();
    }

    /**
     * The top-level service. Its presence as a Spring bean causes
     * HybridHandshakeOrchestrator to use KMS-managed persistent keys
     * instead of ephemeral ones (via Optional<QuantumKeyService> injection).
     */
    @Bean
    @ConditionalOnMissingBean
    QuantumKeyService quantumKeyService(KeyManagementProvider provider, KeyRegistry registry) {
        return new QuantumKeyService(provider, registry);
    }

    @Bean
    @ConditionalOnMissingBean
    KeyRotationManager keyRotationManager(QuantumKeyService keyService,
                                          KeyManagementProperties props) {
        return new KeyRotationManager(keyService, props);
    }
}
