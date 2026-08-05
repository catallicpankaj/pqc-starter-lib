package com.pqc.hybrid.migration.config;

import com.pqc.hybrid.migration.MigrationMode;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.HashMap;
import java.util.Map;

/**
 * Configuration properties for Phase 5 — RSA Migration Bridge.
 *
 * Example application.yml:
 *
 *   spring:
 *     pqc:
 *       migration:
 *         enabled: true
 *         default-mode: BRIDGE
 *         rollout-percentage: 75      # 75% of bridge sessions use PQC
 *         service-overrides:
 *           legacy-billing-svc: RSA_ONLY   # this service stays RSA until migrated
 *           auth-svc: PQC_ONLY             # fully migrated, force PQC
 */
@ConfigurationProperties(prefix = "pqc.migration")
public class RsaMigrationProperties {

    /** Master switch. Default: true. */
    private boolean enabled = true;

    /**
     * Default mode when no per-service override is configured.
     * RSA_ONLY | BRIDGE | PQC_ONLY. Default: BRIDGE.
     */
    private MigrationMode defaultMode = MigrationMode.BRIDGE;

    /**
     * Percentage (0–100) of BRIDGE-mode sessions routed to PQC.
     *   100 = fully rolled out (all bridge sessions use PQC).
     *   0   = no rollout yet (all bridge sessions fall back to RSA).
     *   50  = 50/50 split — for canary / A-B rollout.
     * Default: 100.
     */
    private int rolloutPercentage = 100;

    /**
     * Per-service mode overrides.
     * Key = clientId, Value = forced MigrationMode.
     * Takes precedence over defaultMode and rolloutPercentage for that clientId.
     */
    private Map<String, MigrationMode> serviceOverrides = new HashMap<>();

    public boolean isEnabled()                          { return enabled; }
    public void    setEnabled(boolean v)                { this.enabled = v; }

    public MigrationMode getDefaultMode()               { return defaultMode; }
    public void setDefaultMode(MigrationMode v)         { this.defaultMode = v; }

    public int  getRolloutPercentage()                  { return rolloutPercentage; }
    public void setRolloutPercentage(int v)             { this.rolloutPercentage = Math.max(0, Math.min(100, v)); }

    public Map<String, MigrationMode> getServiceOverrides()              { return serviceOverrides; }
    public void setServiceOverrides(Map<String, MigrationMode> v)        { this.serviceOverrides = v; }
}
