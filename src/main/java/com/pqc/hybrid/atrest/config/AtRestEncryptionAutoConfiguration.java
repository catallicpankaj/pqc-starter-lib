package com.pqc.hybrid.atrest.config;

import com.pqc.hybrid.atrest.*;
import com.pqc.hybrid.crypto.AesGcmEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import java.security.SecureRandom;

/**
 * Spring Boot auto-configuration for Phase 6 Data-at-Rest encryption.
 *
 * Activates when {@code pqc.atrest.enabled=true} (the default).
 * Wires: HkdfKeyDerivation → EncryptedFieldService → ReEncryptionService
 *        StreamingAesGcmEngine → AtRestEncryptionService → AtRestEncryptionController
 *
 * When {@code pqc.atrest.previous-master-key-hex} is set, ReEncryptionService
 * is wired with a second EncryptedFieldService bound to the OLD key, so that values
 * encrypted before a master key rotation remain decryptable while they're re-encrypted
 * under the new key. See {@link AtRestEncryptionProperties} for the rotation procedure.
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "pqc.atrest", name = "enabled", matchIfMissing = true)
@EnableConfigurationProperties(AtRestEncryptionProperties.class)
public class AtRestEncryptionAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(AtRestEncryptionAutoConfiguration.class);

    @Bean
    public HkdfKeyDerivation hkdfKeyDerivation() {
        return new HkdfKeyDerivation();
    }

    @Bean
    public EncryptedFieldService encryptedFieldService(AtRestEncryptionProperties props,
                                                        HkdfKeyDerivation hkdf) {
        byte[] masterKey = resolveCurrentMasterKey(props);
        log.info("AtRest: masterKeyVersion={}, keySource={}",
                props.getMasterKeyVersion(),
                props.getMasterKeyHex().isBlank() ? "random (dev)" : "config");
        return new EncryptedFieldService(new AesGcmEngine(), hkdf, masterKey, props.getMasterKeyVersion());
    }

    @Bean
    public ReEncryptionService reEncryptionService(EncryptedFieldService fieldService,
                                                    AtRestEncryptionProperties props,
                                                    HkdfKeyDerivation hkdf) {
        String previousHex = props.getPreviousMasterKeyHex();
        if (previousHex == null || previousHex.isBlank()) {
            // No rotation in progress — decrypt and re-encrypt use the same key, as before.
            return new ReEncryptionService(fieldService);
        }

        byte[] previousKey = parseKeyHex(previousHex, "pqc.atrest.previous-master-key-hex");
        // The instance-level version on the "previous" service is never consulted by
        // ReEncryptionService (it always uses the explicit version parsed from each
        // stored value's "v{n}:" prefix) — this is a nominal value only.
        int previousVersion = Math.max(0, props.getMasterKeyVersion() - 1);
        EncryptedFieldService previousService =
                new EncryptedFieldService(new AesGcmEngine(), hkdf, previousKey, previousVersion);

        log.info("AtRest: rotation in progress — previousMasterKeyVersion~={}, currentMasterKeyVersion={}",
                previousVersion, props.getMasterKeyVersion());
        return new ReEncryptionService(previousService, fieldService);
    }

    @Bean
    public StreamingAesGcmEngine streamingAesGcmEngine(AtRestEncryptionProperties props) {
        return new StreamingAesGcmEngine(props.getChunkSize());
    }

    @Bean
    public AtRestEncryptionService atRestEncryptionService(EncryptedFieldService fieldService,
                                                            StreamingAesGcmEngine streamEngine,
                                                            ReEncryptionService reEncService) {
        return new AtRestEncryptionService(fieldService, streamEngine, reEncService);
    }

    @Bean
    public AtRestEncryptionController atRestEncryptionController(
            AtRestEncryptionService atRestService,
            AtRestEncryptionProperties props) {
        return new AtRestEncryptionController(atRestService, props);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private byte[] resolveCurrentMasterKey(AtRestEncryptionProperties props) {
        String hex = props.getMasterKeyHex();
        if (hex != null && hex.length() == 64) {
            return parseKeyHex(hex, "pqc.atrest.master-key-hex");
        }
        // Dev-mode: generate a random key (not suitable for production)
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        log.warn("AtRest: no master key configured — using ephemeral random key. " +
                 "Set pqc.atrest.master-key-hex for production use.");
        return key;
    }

    private byte[] parseKeyHex(String hex, String propertyName) {
        if (hex == null || hex.length() != 64) {
            throw new IllegalStateException(
                    propertyName + " must be exactly 64 hex characters (32 bytes), got: " +
                    (hex == null ? "null" : hex.length() + " characters"));
        }
        byte[] key = new byte[32];
        for (int i = 0; i < 32; i++)
            key[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        return key;
    }
}
