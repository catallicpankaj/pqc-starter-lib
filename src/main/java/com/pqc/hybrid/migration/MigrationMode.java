package com.pqc.hybrid.migration;

/**
 * Migration mode for the RSA → Kyber bridge.
 *
 * Controls which key exchange algorithm is used when establishing a session:
 *
 *   RSA_ONLY  — RSA-2048 OAEP key transport (legacy simulation / backward compat testing)
 *   BRIDGE    — Dual-mode: PQC preferred, falls back to RSA for legacy peers.
 *               Rollout is controlled by RsaMigrationProperties.rolloutPercentage.
 *   PQC_ONLY  — Kyber-768 or Hybrid only; refuses RSA path. Use once fully migrated.
 */
public enum MigrationMode {

    RSA_ONLY("RSA-2048 OAEP key transport — legacy, not quantum-safe", false),
    BRIDGE  ("Dual-mode: PQC preferred, RSA fallback for legacy peers", false),
    PQC_ONLY("Kyber-768 / Hybrid only — fully quantum-safe, no RSA fallback", true);

    private final String  description;
    private final boolean alwaysQuantumSafe;

    MigrationMode(String description, boolean alwaysQuantumSafe) {
        this.description       = description;
        this.alwaysQuantumSafe = alwaysQuantumSafe;
    }

    public String  getDescription()      { return description; }
    public boolean isAlwaysQuantumSafe() { return alwaysQuantumSafe; }
}
