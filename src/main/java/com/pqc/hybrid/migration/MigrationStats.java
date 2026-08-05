package com.pqc.hybrid.migration;

/**
 * Snapshot of RSA → PQC migration statistics.
 *
 * Used to measure rollout progress: what percentage of live sessions
 * are now using quantum-safe cryptography vs. legacy RSA.
 *
 * @param rsaSessions          Sessions that used RSA_ONLY path directly
 * @param bridgeToPqcSessions  BRIDGE sessions routed to PQC
 * @param bridgeToRsaSessions  BRIDGE sessions that fell back to RSA
 * @param pqcOnlySessions      Sessions that used PQC_ONLY path directly
 * @param totalSessions        Sum of all session types
 * @param pqcMigrationPercent  Percentage of total sessions that used PQC
 */
public record MigrationStats(
        long   rsaSessions,
        long   bridgeToPqcSessions,
        long   bridgeToRsaSessions,
        long   pqcOnlySessions,
        long   totalSessions,
        double pqcMigrationPercent) {

    /** Sessions that ended up using quantum-safe cryptography. */
    public long quantumSafeSessions() {
        return bridgeToPqcSessions + pqcOnlySessions;
    }
}
