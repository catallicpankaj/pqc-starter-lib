package com.pqc.hybrid.handshake;

/**
 * Negotiated cipher mode for a hybrid handshake session.
 *
 * CLASSICAL  — ECDHE-P384 only. Used for legacy clients.
 * PQC_ONLY   — Kyber-768 only. Quantum-safe, no classical fallback.
 * HYBRID     — ECDHE-P384 + Kyber-768 combined via KDF.
 *              Security: attacker must break BOTH to recover session key.
 */
public enum CipherMode {

    CLASSICAL("Classical ECDHE-P384",               false, false),
    PQC_ONLY ("PQC Only — Kyber-768",               true,  false),
    HYBRID   ("Hybrid ECDHE-P384 + Kyber-768",      true,  true);

    private final String  description;
    private final boolean pqcActive;
    private final boolean hybridActive;

    CipherMode(String description, boolean pqcActive, boolean hybridActive) {
        this.description  = description;
        this.pqcActive    = pqcActive;
        this.hybridActive = hybridActive;
    }

    public String  getDescription() { return description; }
    public boolean isPqcActive()    { return pqcActive; }
    public boolean isHybridActive() { return hybridActive; }
    public boolean isQuantumSafe()  { return pqcActive; }
}
