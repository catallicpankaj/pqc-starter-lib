package com.pqc.hybrid.keymanagement.api;

import java.security.PublicKey;
import java.time.Instant;

/**
 * One versioned entry in the key registry.
 *
 * A key evolves through versions as it is rotated. Multiple versions of the same
 * key ID can exist simultaneously:
 *
 *   V1: DEPRECATED — still valid for unwrapping / decrypting existing data
 *   V2: ACTIVE     — used for all new wrap / encrypt operations
 *
 * This is essential for safe rotation: you must be able to decrypt old data
 * (encrypted with V1) while writing new data encrypted with V2, without a
 * service interruption or data re-encryption delay.
 *
 * LIFECYCLE:
 *   Generated    → ACTIVE
 *   On rotation  → previous ACTIVE becomes DEPRECATED; new key becomes ACTIVE
 *   After window → DEPRECATED becomes RETIRED (no active sessions use it)
 *   RETIRED keys are kept for audit trail but never used for crypto operations.
 */
public class KeyVersion {

    /** Key lifecycle state */
    public enum Status {
        ACTIVE,      // current key — used for all new operations
        DEPRECATED,  // old key — still valid for decryption of existing data
        RETIRED      // no longer used — kept for audit trail only
    }

    /** The algorithm for which this keypair was generated */
    public enum KeyAlgorithm {
        KYBER_768("Kyber-768", "Kyber", "BCPQC"),
        EC_P384("ECDHE-P384",  "EC",    "BC"),
        DILITHIUM_3("Dilithium-3", "Dilithium", "BCPQC");

        private final String label;
        private final String bcAlgorithmName;
        private final String bcProviderName;

        KeyAlgorithm(String label, String bcAlgorithmName, String bcProviderName) {
            this.label           = label;
            this.bcAlgorithmName = bcAlgorithmName;
            this.bcProviderName  = bcProviderName;
        }

        public String getLabel()           { return label; }
        public String getBcAlgorithmName() { return bcAlgorithmName; }
        public String getBcProviderName()  { return bcProviderName; }
    }

    private final String             keyId;
    private final int                version;
    private final KeyAlgorithm       algorithm;
    private final PublicKey          publicKey;
    private final WrappedKeyMaterial wrappedPrivateKey;
    private       Status             status;
    private final Instant            createdAt;
    private       Instant            deprecatedAt;
    private       Instant            retiredAt;

    private KeyVersion(Builder b) {
        this.keyId             = b.keyId;
        this.version           = b.version;
        this.algorithm         = b.algorithm;
        this.publicKey         = b.publicKey;
        this.wrappedPrivateKey = b.wrappedPrivateKey;
        this.status            = b.status;
        this.createdAt         = b.createdAt;
        this.deprecatedAt      = b.deprecatedAt;
        this.retiredAt         = b.retiredAt;
    }

    public String             getKeyId()             { return keyId; }
    public int                getVersion()           { return version; }
    public KeyAlgorithm       getAlgorithm()         { return algorithm; }
    public PublicKey          getPublicKey()          { return publicKey; }
    public WrappedKeyMaterial getWrappedPrivateKey()  { return wrappedPrivateKey; }
    public Status             getStatus()            { return status; }
    public Instant            getCreatedAt()         { return createdAt; }
    public Instant            getDeprecatedAt()      { return deprecatedAt; }
    public Instant            getRetiredAt()         { return retiredAt; }

    /** Can this version be used to decrypt / unwrap existing data? */
    public boolean isUsableForDecryption() {
        return status == Status.ACTIVE || status == Status.DEPRECATED;
    }

    /** Can this version be used for new encrypt / wrap operations? */
    public boolean isUsableForEncryption() {
        return status == Status.ACTIVE;
    }

    /** Transition: ACTIVE → DEPRECATED. Called when a new version becomes ACTIVE. */
    public void deprecate() {
        this.status = Status.DEPRECATED;
        this.deprecatedAt = Instant.now();
    }

    /** Transition: DEPRECATED → RETIRED. Called after the rotation transition window. */
    public void retire() {
        this.status = Status.RETIRED;
        this.retiredAt = Instant.now();
    }

    public static Builder builder() { return new Builder(); }

    public static class Builder {
        private String             keyId;
        private int                version    = 1;
        private KeyAlgorithm       algorithm;
        private PublicKey          publicKey;
        private WrappedKeyMaterial wrappedPrivateKey;
        private Status             status     = Status.ACTIVE;
        private Instant            createdAt  = Instant.now();
        private Instant            deprecatedAt;
        private Instant            retiredAt;

        public Builder keyId(String v)                         { keyId = v;             return this; }
        public Builder version(int v)                          { version = v;           return this; }
        public Builder algorithm(KeyAlgorithm v)               { algorithm = v;         return this; }
        public Builder publicKey(PublicKey v)                   { publicKey = v;         return this; }
        public Builder wrappedPrivateKey(WrappedKeyMaterial v)  { wrappedPrivateKey = v; return this; }
        public Builder status(Status v)                        { status = v;            return this; }
        /** Overrides the default (now) — mainly for tests exercising age-based rotation/retirement logic. */
        public Builder createdAt(Instant v)                    { createdAt = v;         return this; }
        public Builder deprecatedAt(Instant v)                 { deprecatedAt = v;      return this; }
        public Builder retiredAt(Instant v)                    { retiredAt = v;         return this; }
        public KeyVersion build()                              { return new KeyVersion(this); }
    }
}
