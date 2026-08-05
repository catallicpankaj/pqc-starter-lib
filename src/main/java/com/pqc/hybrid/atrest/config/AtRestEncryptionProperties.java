package com.pqc.hybrid.atrest.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for Phase 6 Data-at-Rest encryption.
 *
 * <pre>{@code
 * spring:
 *   pqc:
 *     atrest:
 *       enabled: true
 *       master-key-hex: ""          # 64-hex-char (32-byte) key; auto-generated if blank
 *       master-key-version: 1       # increment after key rotation
 *       previous-master-key-hex: "" # OLD 64-hex-char key — required during rotation, see below
 *       chunk-size: 4096            # streaming chunk size in bytes
 * }</pre>
 *
 * <b>Rotating the master key without losing existing data:</b> setting
 * {@code master-key-hex} to a new value and bumping {@code master-key-version} is
 * NOT enough by itself — every value already encrypted under the old key becomes
 * undecryptable unless the old key material is also still available. Set
 * {@code previous-master-key-hex} to the OLD {@code master-key-hex} value for as
 * long as any data may still be encrypted under it (i.e. until a full lazy or
 * eager re-encryption pass has completed), then remove it.
 */
@ConfigurationProperties(prefix = "pqc.atrest")
public class AtRestEncryptionProperties {

    /** Enable/disable the at-rest encryption auto-configuration. */
    private boolean enabled = true;

    /**
     * 32-byte master key as 64 hex characters.
     * Leave blank to have the library generate a random key at startup
     * (suitable for development; for production always provide a stable key).
     */
    private String masterKeyHex = "";

    /**
     * Current master key version. Stored in every encrypted value as "v{n}:".
     * Increment this value after rotating to a new masterKeyHex.
     * Existing values encrypted under old versions will be lazily re-encrypted
     * on the next read (or eagerly via the /api/atrest/reencrypt batch endpoint).
     */
    private int masterKeyVersion = 1;

    /**
     * The PREVIOUS 32-byte master key as 64 hex characters — required during a
     * key rotation so that values encrypted under the old key can still be
     * decrypted and re-encrypted under the new one. Leave blank when there is
     * no rotation in progress (the default — decryption then uses the same key
     * as encryption, as before this property existed).
     *
     * Rotation procedure:
     *   1. Set previous-master-key-hex to the CURRENT master-key-hex value.
     *   2. Set master-key-hex to the NEW key, and increment master-key-version.
     *   3. Deploy. Old values now decrypt via previous-master-key-hex and
     *      re-encrypt (lazily on read, or via the reencrypt-field endpoint /
     *      an eager batch job) under the new key.
     *   4. Once every stored value has been re-encrypted (no more "v{oldVersion}:"
     *      values remain), remove previous-master-key-hex.
     */
    private String previousMasterKeyHex = "";

    /**
     * Plaintext bytes per chunk for streaming file encryption.
     * Default 4096 (4 KB) — increase for throughput, decrease for memory pressure.
     */
    private int chunkSize = 4096;

    // ── Getters / Setters ────────────────────────────────────────────────────

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public String getMasterKeyHex() { return masterKeyHex; }
    public void setMasterKeyHex(String masterKeyHex) { this.masterKeyHex = masterKeyHex; }

    public int getMasterKeyVersion() { return masterKeyVersion; }
    public void setMasterKeyVersion(int masterKeyVersion) { this.masterKeyVersion = masterKeyVersion; }

    public String getPreviousMasterKeyHex() { return previousMasterKeyHex; }
    public void setPreviousMasterKeyHex(String previousMasterKeyHex) { this.previousMasterKeyHex = previousMasterKeyHex; }

    public int getChunkSize() { return chunkSize; }
    public void setChunkSize(int chunkSize) { this.chunkSize = chunkSize; }
}
