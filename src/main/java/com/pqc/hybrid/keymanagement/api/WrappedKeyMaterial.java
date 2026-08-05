package com.pqc.hybrid.keymanagement.api;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

/**
 * Immutable model holding the output of a KMS wrap operation.
 *
 * Safe to store in a database, file, or secret store — contains the encrypted
 * private key bytes but NOT the raw private key. The raw private key can only
 * be recovered by calling KeyManagementProvider.unwrapKey() with the same
 * provider that performed the original wrap.
 *
 * Fields:
 *   keyId        — logical key identifier (matches the keyId used in wrapKey())
 *   version      — version number for rotation tracking (1-based)
 *   wrappedBytes — the encrypted private key (opaque; format is provider-specific)
 *                  Vault: the raw Base64-decoded bytes of the Vault ciphertext string
 *                  AWS:   the EncryptedDataKey blob from GenerateDataKey
 *                  Local: AES-256-GCM ciphertext (IV prepended)
 *   algorithm    — wrapping algorithm for auditability
 *                  Vault: "vault-transit-aes256-gcm96" (Vault's default)
 *                  AWS:   "aws-kms-aes256"
 *                  Local: "AES/GCM/NoPadding"
 *   providerName — which provider performed the wrap (matches KeyManagementProvider.providerName())
 *   context      — provider-specific metadata for unwrapping:
 *                  Vault: full "vault:v{N}:..." ciphertext string (needed for decrypt call)
 *                  AWS:   KeyId ARN used for wrapping
 *                  Local: empty string (key is self-contained)
 *   wrappedAt    — timestamp for audit trail and rotation age calculation
 */
public record WrappedKeyMaterial(
    String  keyId,
    int     version,
    byte[]  wrappedBytes,
    String  algorithm,
    String  providerName,
    String  context,
    Instant wrappedAt
) {
    /** Convenience factory — sets wrappedAt to now */
    public static WrappedKeyMaterial of(
            String keyId, int version, byte[] wrappedBytes,
            String algorithm, String providerName, String context) {
        return new WrappedKeyMaterial(keyId, version, wrappedBytes,
                                      algorithm, providerName, context, Instant.now());
    }

    /**
     * Records' auto-generated equals()/hashCode() compare byte[] components by
     * reference (Objects.equals delegates to Object.equals for arrays), not by
     * content — overridden here so two WrappedKeyMaterial instances with the
     * same wrapped bytes (e.g. round-tripped through storage) compare equal.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof WrappedKeyMaterial other)) return false;
        return version == other.version
            && Objects.equals(keyId, other.keyId)
            && Arrays.equals(wrappedBytes, other.wrappedBytes)
            && Objects.equals(algorithm, other.algorithm)
            && Objects.equals(providerName, other.providerName)
            && Objects.equals(context, other.context)
            && Objects.equals(wrappedAt, other.wrappedAt);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(keyId, version, algorithm, providerName, context, wrappedAt);
        return 31 * result + Arrays.hashCode(wrappedBytes);
    }
}
