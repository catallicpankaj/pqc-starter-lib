package com.pqc.hybrid.migration.config;

import com.pqc.hybrid.handshake.HybridHandshakeOrchestrator;
import com.pqc.hybrid.migration.RsaKeyConverter;
import com.pqc.hybrid.migration.RsaKyberBridgeService;
import com.pqc.hybrid.migration.RsaMigrationController;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Auto-configuration for Phase 5 — RSA Migration Bridge.
 *
 * Activated when pqc.migration.enabled=true (the default) AND a
 * HybridHandshakeOrchestrator bean is present. The @ConditionalOnBean guard means this
 * whole module quietly no-ops — rather than crashing application startup — when
 * pqc.enabled=false has removed Phase 1/2's core orchestrator bean; the migration
 * bridge's PQC-path modes are meaningless without it.
 *
 * Disable entirely:
 *   pqc.migration.enabled=false
 */
@AutoConfiguration
@ConditionalOnProperty(
        prefix = "pqc.migration",
        name   = "enabled",
        havingValue = "true",
        matchIfMissing = true)
@ConditionalOnBean(HybridHandshakeOrchestrator.class)
@EnableConfigurationProperties(RsaMigrationProperties.class)
public class RsaMigrationAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    RsaKeyConverter rsaKeyConverter() throws Exception {
        return new RsaKeyConverter();
    }

    @Bean
    @ConditionalOnMissingBean
    RsaKyberBridgeService rsaKyberBridgeService(
            RsaKeyConverter rsaKeyConverter,
            HybridHandshakeOrchestrator orchestrator,
            RsaMigrationProperties props) {
        return new RsaKyberBridgeService(rsaKeyConverter, orchestrator, props);
    }

    @Bean
    @ConditionalOnMissingBean
    RsaMigrationController rsaMigrationController(
            RsaKyberBridgeService bridgeService,
            RsaMigrationProperties props) {
        return new RsaMigrationController(bridgeService, props);
    }
}
