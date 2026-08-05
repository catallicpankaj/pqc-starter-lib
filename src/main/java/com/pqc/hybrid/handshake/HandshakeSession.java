package com.pqc.hybrid.handshake;

import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;

/**
 * Result of a completed hybrid handshake.
 * Contains the negotiated mode, combined session key material, and metadata.
 *
 * IMPORTANT: Never expose sessionKeyMaterial via API.
 * Always use toSummary() for external consumption.
 */
public class HandshakeSession {

    private final String      sessionId;
    private final CipherMode  cipherMode;
    private final byte[]      sessionKeyMaterial;
    private final String      clientId;
    private final String      classicalAlgorithm;
    private final String      pqcKemAlgorithm;
    private final long        handshakeDurationNs;
    private final boolean     quantumSafe;
    private final Instant     createdAt;

    private HandshakeSession(Builder b) {
        this.sessionId           = b.sessionId;
        this.cipherMode          = b.cipherMode;
        this.sessionKeyMaterial  = b.sessionKeyMaterial;
        this.clientId            = b.clientId;
        this.classicalAlgorithm  = b.classicalAlgorithm;
        this.pqcKemAlgorithm     = b.pqcKemAlgorithm;
        this.handshakeDurationNs = b.handshakeDurationNs;
        this.quantumSafe         = b.quantumSafe;
        this.createdAt           = Instant.now();
    }

    public String     getSessionId()            { return sessionId; }
    public CipherMode getCipherMode()           { return cipherMode; }
    public byte[]     getSessionKeyMaterial()   { return Arrays.copyOf(sessionKeyMaterial, sessionKeyMaterial.length); }
    public String     getClientId()             { return clientId; }
    public String     getClassicalAlgorithm()   { return classicalAlgorithm != null ? classicalAlgorithm : "none"; }
    public String     getPqcKemAlgorithm()      { return pqcKemAlgorithm != null ? pqcKemAlgorithm : "none"; }
    public long       getHandshakeDurationNs()  { return handshakeDurationNs; }
    public double     getHandshakeDurationMs()  { return handshakeDurationNs / 1_000_000.0; }
    public boolean    isQuantumSafe()           { return quantumSafe; }
    public Instant    getCreatedAt()            { return createdAt; }

    /** Safe public DTO — no key material, only fingerprint */
    public SessionSummary toSummary() {
        String fingerprint = Base64.getEncoder()
            .encodeToString(Arrays.copyOf(sessionKeyMaterial, 8)) + "...";
        return new SessionSummary(
            sessionId, cipherMode.name(), cipherMode.getDescription(),
            clientId, getClassicalAlgorithm(), getPqcKemAlgorithm(),
            getHandshakeDurationMs(), quantumSafe, createdAt.toString(), fingerprint
        );
    }

    public static Builder builder() { return new Builder(); }

    public static class Builder {
        private String     sessionId;
        private CipherMode cipherMode;
        private byte[]     sessionKeyMaterial;
        private String     clientId;
        private String     classicalAlgorithm;
        private String     pqcKemAlgorithm;
        private long       handshakeDurationNs;
        private boolean    quantumSafe;

        public Builder sessionId(String v)            { sessionId = v;            return this; }
        public Builder cipherMode(CipherMode v)       { cipherMode = v;           return this; }
        public Builder sessionKeyMaterial(byte[] v)   { sessionKeyMaterial = v;   return this; }
        public Builder clientId(String v)             { clientId = v;             return this; }
        public Builder classicalAlgorithm(String v)   { classicalAlgorithm = v;   return this; }
        public Builder pqcKemAlgorithm(String v)      { pqcKemAlgorithm = v;      return this; }
        public Builder handshakeDurationNs(long v)    { handshakeDurationNs = v;  return this; }
        public Builder quantumSafe(boolean v)         { quantumSafe = v;          return this; }
        public HandshakeSession build()               { return new HandshakeSession(this); }
    }

    public record SessionSummary(
        String  sessionId,
        String  cipherMode,
        String  cipherModeDescription,
        String  clientId,
        String  classicalAlgorithm,
        String  pqcKemAlgorithm,
        double  handshakeDurationMs,
        boolean quantumSafe,
        String  createdAt,
        String  keyFingerprint
    ) {}
}
