package com.pqc.hybrid.autoconfigure;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pqc.hybrid.atrest.AtRestEncryptionController;
import com.pqc.hybrid.atrest.AtRestEncryptionService;
import com.pqc.hybrid.atrest.config.AtRestEncryptionAutoConfiguration;
import com.pqc.hybrid.crypto.AesGcmEngine;
import com.pqc.hybrid.crypto.PqcEncryptionService;
import com.pqc.hybrid.crypto.PqcKeyPairGenerator;
import com.pqc.hybrid.handshake.HybridHandshakeOrchestrator;
import com.pqc.hybrid.handshake.KyberKemEngine;
import com.pqc.hybrid.jwt.DilithiumJwtAuthController;
import com.pqc.hybrid.keymanagement.api.KeyManagementProvider;
import com.pqc.hybrid.keymanagement.config.KeyManagementAutoConfiguration;
import com.pqc.hybrid.keymanagement.providers.LocalDevKeyProvider;
import com.pqc.hybrid.keymanagement.service.QuantumKeyService;
import com.pqc.hybrid.migration.RsaKyberBridgeService;
import com.pqc.hybrid.migration.RsaMigrationController;
import com.pqc.hybrid.migration.config.RsaMigrationAutoConfiguration;
import com.pqc.hybrid.signing.PqcSignatureService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.*;

/**
 * Verifies the four {@code @AutoConfiguration} classes actually wire correctly through
 * Spring's DI container — the layer none of the other tests touch, since every other
 * test in this suite constructs its subjects with plain {@code new}. This is the exact
 * gap that let the "PqcEncryptionService never registered as a bean" bug and the
 * "actuator never got QuantumKeyService" bug ship undetected: both existed entirely at
 * the wiring layer, invisible to unit tests that bypass Spring altogether.
 */
class PqcAutoConfigurationWiringTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(
            PqcAutoConfiguration.class,
            KeyManagementAutoConfiguration.class,
            RsaMigrationAutoConfiguration.class,
            AtRestEncryptionAutoConfiguration.class))
        .withBean(ObjectMapper.class, ObjectMapper::new);

    @Test
    @DisplayName("Default context: core Phase 1/2 beans are registered, including PqcEncryptionService")
    void defaultContextRegistersCoreBeans() {
        runner.run(context -> {
            assertThat(context).hasSingleBean(HybridHandshakeOrchestrator.class);
            assertThat(context).hasSingleBean(KyberKemEngine.class);
            assertThat(context).hasSingleBean(AesGcmEngine.class);
            // This exact bean was missing entirely in a previous revision — regression guard.
            assertThat(context).hasSingleBean(PqcEncryptionService.class);
        });
    }

    @Test
    @DisplayName("Default context: PqcSignatureService and PqcKeyPairGenerator are registered without any config")
    void defaultContextRegistersSignatureAndKeyGenBeans() {
        runner.run(context -> {
            assertThat(context).hasSingleBean(PqcSignatureService.class);
            assertThat(context).hasSingleBean(PqcKeyPairGenerator.class);
        });
    }

    @Test
    @DisplayName("Default context: Phase 5 (migration) and Phase 6 (at-rest) beans are registered — both default to enabled=true")
    void defaultContextRegistersMigrationAndAtRestBeans() {
        runner.run(context -> {
            assertThat(context).hasSingleBean(RsaKyberBridgeService.class);
            assertThat(context).hasSingleBean(RsaMigrationController.class);
            assertThat(context).hasSingleBean(AtRestEncryptionService.class);
            assertThat(context).hasSingleBean(AtRestEncryptionController.class);
        });
    }

    @Test
    @DisplayName("Default context: Phase 4 JWT auth controller is registered without any config")
    void defaultContextRegistersJwtBeans() {
        runner.run(context -> assertThat(context).hasSingleBean(DilithiumJwtAuthController.class));
    }

    @Test
    @DisplayName("Default context: Phase 3 (key management) beans are ABSENT — no provider configured")
    void defaultContextDoesNotRegisterKeyManagementBeans() {
        runner.run(context -> {
            assertThat(context).doesNotHaveBean(QuantumKeyService.class);
            assertThat(context).doesNotHaveBean(KeyManagementProvider.class);
        });
    }

    @Test
    @DisplayName("pqc.enabled=false: PqcAutoConfiguration beans are absent, and the context still starts")
    void pqcDisabledRemovesCoreBeans() {
        // Regression guard: RsaMigrationAutoConfiguration used to have a hard (non-optional)
        // dependency on HybridHandshakeOrchestrator, so disabling the "master switch" crashed
        // the entire application at startup (UnsatisfiedDependencyException) rather than just
        // omitting Phase 1/2's beans — @ConditionalOnBean fixed this; assertThat(context) below
        // would surface a startup failure immediately if that regressed.
        runner.withPropertyValues("pqc.enabled=false")
            .run(context -> {
                assertThat(context).hasNotFailed();
                assertThat(context).doesNotHaveBean(HybridHandshakeOrchestrator.class);
                assertThat(context).doesNotHaveBean(PqcEncryptionService.class);
                // The migration module depends on the orchestrator — it must gracefully no-op,
                // not crash the context, when the orchestrator it needs isn't available.
                assertThat(context).doesNotHaveBean(RsaKyberBridgeService.class);
                assertThat(context).doesNotHaveBean(RsaMigrationController.class);
                // At-rest is independent of the orchestrator — must be unaffected.
                assertThat(context).hasSingleBean(AtRestEncryptionService.class);
            });
    }

    @Test
    @DisplayName("pqc.migration.enabled=false: migration beans are absent, everything else unaffected")
    void migrationDisabledRemovesOnlyMigrationBeans() {
        runner.withPropertyValues("pqc.migration.enabled=false")
            .run(context -> {
                assertThat(context).doesNotHaveBean(RsaKyberBridgeService.class);
                assertThat(context).doesNotHaveBean(RsaMigrationController.class);
                // Phase 1/2/6 must still be present — disabling one module doesn't disable the rest
                assertThat(context).hasSingleBean(PqcEncryptionService.class);
                assertThat(context).hasSingleBean(AtRestEncryptionService.class);
            });
    }

    @Test
    @DisplayName("pqc.atrest.enabled=false: at-rest beans are absent, everything else unaffected")
    void atRestDisabledRemovesOnlyAtRestBeans() {
        runner.withPropertyValues("pqc.atrest.enabled=false")
            .run(context -> {
                assertThat(context).doesNotHaveBean(AtRestEncryptionService.class);
                assertThat(context).doesNotHaveBean(AtRestEncryptionController.class);
                assertThat(context).hasSingleBean(PqcEncryptionService.class);
                assertThat(context).hasSingleBean(RsaKyberBridgeService.class);
            });
    }

    @Test
    @DisplayName("pqc.key-management.provider=local: Phase 3 activates, LocalDevKeyProvider is selected")
    void localProviderActivatesKeyManagement() {
        String tempKeyPath = System.getProperty("java.io.tmpdir") +
            "/pqc-autoconfig-wiring-test-" + System.currentTimeMillis() + "/local-master.key";

        runner.withPropertyValues(
                "pqc.key-management.provider=local",
                "pqc.key-management.local.key-store-path=" + tempKeyPath,
                "pqc.key-management.local.auto-generate=true")
            .run(context -> {
                assertThat(context).hasSingleBean(QuantumKeyService.class);
                assertThat(context).hasSingleBean(KeyManagementProvider.class);
                assertThat(context.getBean(KeyManagementProvider.class)).isInstanceOf(LocalDevKeyProvider.class);
                // Presence of QuantumKeyService must cause the orchestrator to use KMS-managed keys
                assertThat(context.getBean(HybridHandshakeOrchestrator.class).getServerKyberPublicKey())
                    .isEqualTo(context.getBean(QuantumKeyService.class).getActiveKyberKeyPair().getPublic());
            });
    }

    @Test
    @DisplayName("@ConditionalOnMissingBean: a user-supplied PqcEncryptionService bean overrides the auto-configured one")
    void userBeanOverridesAutoConfiguredBean() {
        runner.withUserConfiguration(UserSuppliedEncryptionServiceConfig.class)
            .run(context -> {
                assertThat(context).hasSingleBean(PqcEncryptionService.class);
                assertThat(context.getBean(PqcEncryptionService.class))
                    .isSameAs(UserSuppliedEncryptionServiceConfig.INSTANCE);
            });
    }

    @Test
    @DisplayName("@ConditionalOnMissingBean: a user-supplied PqcSignatureService bean overrides the auto-configured one")
    void userBeanOverridesAutoConfiguredSignatureService() {
        runner.withUserConfiguration(UserSuppliedSignatureServiceConfig.class)
            .run(context -> {
                assertThat(context).hasSingleBean(PqcSignatureService.class);
                assertThat(context.getBean(PqcSignatureService.class))
                    .isSameAs(UserSuppliedSignatureServiceConfig.INSTANCE);
                // Overriding one bean must not affect the others.
                assertThat(context).hasSingleBean(PqcKeyPairGenerator.class);
            });
    }

    @Configuration
    static class UserSuppliedSignatureServiceConfig {
        static PqcSignatureService INSTANCE;

        @Bean
        PqcSignatureService pqcSignatureService(com.pqc.hybrid.signing.DilithiumSigningEngine dilithium) {
            INSTANCE = new PqcSignatureService(dilithium);
            return INSTANCE;
        }
    }

    @Configuration
    static class UserSuppliedEncryptionServiceConfig {
        // A plain hand-built instance (not a mocking-framework proxy) — simplest possible
        // stand-in for "the consuming application supplies its own bean of this type".
        static PqcEncryptionService INSTANCE;

        @Bean
        PqcEncryptionService pqcEncryptionService(HybridHandshakeOrchestrator orchestrator,
                                                   AesGcmEngine aesGcm,
                                                   com.pqc.hybrid.handshake.KyberKemEngine kyberKemEngine) {
            INSTANCE = new PqcEncryptionService(orchestrator, aesGcm, kyberKemEngine);
            return INSTANCE;
        }
    }
}
