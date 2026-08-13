package com.pqc.hybrid.autoconfigure;

import com.pqc.hybrid.actuator.PqcActuatorEndpoint;
import com.pqc.hybrid.crypto.AesGcmEngine;
import com.pqc.hybrid.crypto.PqcEncryptionService;
import com.pqc.hybrid.crypto.PqcKeyPairGenerator;
import com.pqc.hybrid.filter.HybridHandshakeFilter;
import com.pqc.hybrid.handshake.HybridHandshakeOrchestrator;
import com.pqc.hybrid.handshake.KyberKemEngine;
import com.pqc.hybrid.jwt.DilithiumJwtAuthController;
import com.pqc.hybrid.jwt.DilithiumJwtFilter;
import com.pqc.hybrid.jwt.DilithiumJwtService;
import com.pqc.hybrid.jwt.DilithiumKeyPairHolder;
import com.pqc.hybrid.keymanagement.service.QuantumKeyService;
import com.pqc.hybrid.signing.DilithiumSigningEngine;
import com.pqc.hybrid.signing.PqcSignatureService;
import com.pqc.hybrid.signing.SphincsSigningEngine;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import tools.jackson.databind.ObjectMapper;

import java.security.Security;
import java.util.Optional;

/**
 * Spring Boot Auto-configuration for Hybrid PQC Handshake + Signing + JWT.
 *
 * To USE this starter in another project:
 *   1. Add this jar as a dependency
 *   2. Ensure bcprov-jdk18on is on the classpath
 *   3. Optionally configure via application.yml:
 *
 *        pqc.enabled=true   (default: true)
 *
 * Beans registered:
 *   - HybridHandshakeOrchestrator  (Kyber + ECDHE runtime switching)
 *   - HybridHandshakeFilter        (per-request mode switching)
 *   - KyberKemEngine               (Kyber-768 KEM, standalone bean)
 *   - AesGcmEngine                 (AES-256-GCM authenticated encryption)
 *   - PqcEncryptionService         (session-based AND public-key-addressed encrypt/decrypt)
 *   - PqcSignatureService          (Dilithium-3 sign/verify facade)
 *   - PqcKeyPairGenerator          (generates Kyber/Dilithium key pairs)
 *   - DilithiumSigningEngine       (quantum-safe signing)
 *   - SphincsSigningEngine         (hash-based signing)
 *   - PqcActuatorEndpoint          (/actuator/pqc)
 *   - DilithiumKeyPairHolder       (manages Dilithium signing keypair)
 *   - DilithiumJwtService          (issue + validate Dilithium-3 JWTs)
 *   - DilithiumJwtFilter           (Spring Security Bearer token filter)
 *   - DilithiumJwtAuthController   (POST /auth/token, GET /api/secure)
 */
@AutoConfiguration
@ConditionalOnClass({ BouncyCastleProvider.class, BouncyCastlePQCProvider.class })
@ConditionalOnProperty(prefix = "pqc", name = "enabled", havingValue = "true", matchIfMissing = true)
public class PqcAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    HybridHandshakeOrchestrator hybridHandshakeOrchestrator(
            Optional<QuantumKeyService> quantumKeyService) throws Exception {
        if (Security.getProvider("BC")    == null) Security.insertProviderAt(new BouncyCastleProvider(),    1);
        if (Security.getProvider("BCPQC") == null) Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);
        return new HybridHandshakeOrchestrator(quantumKeyService);
    }

    @Bean
    @ConditionalOnMissingBean
    HybridHandshakeFilter hybridHandshakeFilter(HybridHandshakeOrchestrator orchestrator) {
        return new HybridHandshakeFilter(orchestrator);
    }

    @Bean
    @ConditionalOnMissingBean
    KyberKemEngine kyberKemEngine() {
        return new KyberKemEngine();
    }

    @Bean
    @ConditionalOnMissingBean
    AesGcmEngine aesGcmEngine() {
        return new AesGcmEngine();
    }

    @Bean
    @ConditionalOnMissingBean
    PqcEncryptionService pqcEncryptionService(
            HybridHandshakeOrchestrator orchestrator, AesGcmEngine aesGcmEngine,
            KyberKemEngine kyberKemEngine) {
        return new PqcEncryptionService(orchestrator, aesGcmEngine, kyberKemEngine);
    }

    @Bean
    @ConditionalOnMissingBean
    DilithiumSigningEngine dilithiumSigningEngine() {
        return new DilithiumSigningEngine();
    }

    @Bean
    @ConditionalOnMissingBean
    SphincsSigningEngine sphincsSigningEngine() {
        return new SphincsSigningEngine();
    }

    @Bean
    @ConditionalOnMissingBean
    PqcSignatureService pqcSignatureService(DilithiumSigningEngine dilithiumSigningEngine) {
        return new PqcSignatureService(dilithiumSigningEngine);
    }

    @Bean
    @ConditionalOnMissingBean
    PqcKeyPairGenerator pqcKeyPairGenerator(
            KyberKemEngine kyberKemEngine, DilithiumSigningEngine dilithiumSigningEngine) {
        return new PqcKeyPairGenerator(kyberKemEngine, dilithiumSigningEngine);
    }

    @Bean
    @ConditionalOnMissingBean
    PqcActuatorEndpoint pqcActuatorEndpoint(HybridHandshakeOrchestrator orchestrator,
                                             Optional<QuantumKeyService> quantumKeyService) {
        return new PqcActuatorEndpoint(orchestrator, quantumKeyService);
    }

    // ── Phase 4: JWT beans ────────────────────────────────────────

    @Bean
    @ConditionalOnMissingBean
    DilithiumKeyPairHolder dilithiumKeyPairHolder(
            Optional<QuantumKeyService> quantumKeyService) throws Exception {
        return new DilithiumKeyPairHolder(quantumKeyService);
    }

    @Bean
    @ConditionalOnMissingBean
    DilithiumJwtService dilithiumJwtService(
            DilithiumKeyPairHolder keyHolder,
            ObjectMapper mapper,
            @Value("${pqc.jwt.ttl-minutes:60}") long ttlMinutes) {
        return new DilithiumJwtService(keyHolder, mapper, ttlMinutes);
    }

    @Bean
    @ConditionalOnMissingBean
    DilithiumJwtFilter dilithiumJwtFilter(DilithiumJwtService jwtService) {
        return new DilithiumJwtFilter(jwtService);
    }

    @Bean
    @ConditionalOnMissingBean
    DilithiumJwtAuthController dilithiumJwtAuthController(
            DilithiumJwtService jwtService,
            @Value("${pqc.jwt.demo-password:secret}") String demoPassword) {
        return new DilithiumJwtAuthController(jwtService, demoPassword);
    }
}
