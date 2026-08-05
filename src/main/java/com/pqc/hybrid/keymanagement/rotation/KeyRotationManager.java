package com.pqc.hybrid.keymanagement.rotation;

import com.pqc.hybrid.keymanagement.api.KeyVersion;
import com.pqc.hybrid.keymanagement.config.KeyManagementProperties;
import com.pqc.hybrid.keymanagement.service.QuantumKeyService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

/**
 * Scheduled key rotation manager.
 *
 * Runs on a configurable cron schedule (default: daily at 2am) and:
 *   1. Checks if each active key has exceeded its rotation interval.
 *   2. If yes: triggers rotation via QuantumKeyService.rotate(keyId).
 *   3. Checks if any deprecated keys have exceeded the deprecation window.
 *   4. If yes: retires them via QuantumKeyService.retireDeprecated(keyId).
 *
 * ENABLE ROTATION:
 *   pqc.key-management.rotation.enabled=true
 *   pqc.key-management.rotation.interval-days=90
 *   pqc.key-management.rotation.deprecation-window-days=7
 *   pqc.key-management.rotation.cron=0 0 2 * * *
 *
 * MANUAL ROTATION:
 *   Call triggerRotationNow() directly from your code or via an admin endpoint.
 *   This is useful for emergency rotation or testing.
 */
public class KeyRotationManager {

    private static final Logger log = LoggerFactory.getLogger(KeyRotationManager.class);

    private final QuantumKeyService           keyService;
    private final KeyManagementProperties     props;

    private static final List<String> MANAGED_KEY_IDS = List.of(
        QuantumKeyService.KEY_KYBER,
        QuantumKeyService.KEY_EC,
        QuantumKeyService.KEY_DILITHIUM
    );

    public KeyRotationManager(QuantumKeyService keyService, KeyManagementProperties props) {
        this.keyService = keyService;
        this.props      = props;
    }

    // ─────────────────────────────────────────────────────────────
    // Scheduled rotation check
    // ─────────────────────────────────────────────────────────────

    /**
     * Runs on the configured cron schedule.
     * Checks all managed keys and rotates any that have exceeded the interval.
     * Also retires deprecated keys that have passed the deprecation window.
     */
    @Scheduled(cron = "${pqc.key-management.rotation.cron:0 0 2 * * *}")
    public void scheduledRotationCheck() {
        if (!props.getRotation().isEnabled()) {
            log.debug("[rotation] scheduled check skipped — rotation.enabled=false");
            return;
        }

        log.info("[rotation] scheduled check running — interval={}d deprecation-window={}d",
            props.getRotation().getIntervalDays(),
            props.getRotation().getDeprecationWindowDays());

        for (String keyId : MANAGED_KEY_IDS) {
            try {
                checkAndRotate(keyId);
                checkAndRetireDeprecated(keyId);
            } catch (Exception e) {
                log.error("[rotation] error processing keyId={}: {}", keyId, e.getMessage(), e);
            }
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Manual / programmatic rotation
    // ─────────────────────────────────────────────────────────────

    /**
     * Immediately rotates all managed keys regardless of interval.
     * Useful for emergency rotation or testing.
     */
    public void triggerRotationNow() {
        log.warn("[rotation] manual rotation triggered for all keys");
        for (String keyId : MANAGED_KEY_IDS) {
            try {
                keyService.rotate(keyId);
            } catch (Exception e) {
                log.error("[rotation] manual rotation failed for keyId={}: {}", keyId, e.getMessage(), e);
            }
        }
    }

    /**
     * Immediately rotates a specific key.
     *
     * @param keyId the key to rotate (e.g. QuantumKeyService.KEY_KYBER)
     */
    public void triggerRotationNow(String keyId) throws Exception {
        log.warn("[rotation] manual rotation triggered for keyId={}", keyId);
        keyService.rotate(keyId);
    }

    // ─────────────────────────────────────────────────────────────
    // Internal helpers
    // ─────────────────────────────────────────────────────────────

    private void checkAndRotate(String keyId) throws Exception {
        KeyVersion active = keyService.getRegistry().getActive(keyId);
        long ageInDays = ChronoUnit.DAYS.between(active.getCreatedAt(), Instant.now());
        long intervalDays = props.getRotation().getIntervalDays();

        if (ageInDays >= intervalDays) {
            log.info("[rotation] key {} is {} days old (interval={}d) — rotating",
                keyId, ageInDays, intervalDays);
            keyService.rotate(keyId);
        } else {
            log.debug("[rotation] key {} is {} days old (interval={}d) — no rotation needed",
                keyId, ageInDays, intervalDays);
        }
    }

    private void checkAndRetireDeprecated(String keyId) throws Exception {
        long windowDays = props.getRotation().getDeprecationWindowDays();
        List<KeyVersion> deprecated = keyService.getRegistry().getAll(keyId).stream()
            .filter(kv -> kv.getStatus() == KeyVersion.Status.DEPRECATED)
            .filter(kv -> kv.getDeprecatedAt() != null &&
                          ChronoUnit.DAYS.between(kv.getDeprecatedAt(), Instant.now()) >= windowDays)
            .toList();

        if (!deprecated.isEmpty()) {
            log.info("[rotation] retiring {} deprecated version(s) of keyId={}", deprecated.size(), keyId);
            keyService.retireDeprecated(keyId);
        }
    }
}
