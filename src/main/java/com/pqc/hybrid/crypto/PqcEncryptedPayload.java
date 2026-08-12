package com.pqc.hybrid.crypto;

import java.util.Arrays;

/**
 * Wire format for the public-key-addressed encryption API — {@link PqcEncryptionService#encrypt}
 * and {@link PqcEncryptionService#decrypt(PqcEncryptedPayload, java.security.PrivateKey)}.
 *
 * Unlike the session-based {@code AesGcmEngine.EncryptedPayload}, this carries the Kyber-768
 * encapsulated key alongside the AES-256-GCM ciphertext, so a recipient can recover the shared
 * secret and decrypt using only their own private key — no prior handshake or shared session state
 * required. This is what makes it usable as a REST request/response body (e.g.
 * {@code @RequestBody PqcEncryptedPayload}) between two independent services that never share a
 * live session.
 *
 * Fields:
 *   encapsulatedKey — the Kyber-768 KEM ciphertext (fixed 1088 bytes); decapsulating this with the
 *                      recipient's private key recovers the same 32-byte shared secret used as the
 *                      AES-256 key on the sender's side
 *   iv               — 12-byte random AES-GCM nonce, fresh per encryption
 *   ciphertext        — AES-256-GCM ciphertext + 16-byte authentication tag
 */
public record PqcEncryptedPayload(
    byte[] encapsulatedKey,
    byte[] iv,
    byte[] ciphertext
) {
    /** Kyber-768 KEM ciphertext is always exactly this many bytes (FIPS 203 fixed size). */
    static final int ENCAPSULATED_KEY_LENGTH_BYTES = 1088;
    static final int IV_LENGTH_BYTES = 12;

    /**
     * Serializes to a single byte array: {@code encapsulatedKey || iv || ciphertext}. Both
     * {@code encapsulatedKey} and {@code iv} are fixed-size, so no length prefixes are needed —
     * same convention as {@code AesGcmEngine.toBase64Wire()}.
     */
    public byte[] toBytes() {
        byte[] wire = new byte[encapsulatedKey.length + iv.length + ciphertext.length];
        System.arraycopy(encapsulatedKey, 0, wire, 0, encapsulatedKey.length);
        System.arraycopy(iv, 0, wire, encapsulatedKey.length, iv.length);
        System.arraycopy(ciphertext, 0, wire, encapsulatedKey.length + iv.length, ciphertext.length);
        return wire;
    }

    /** Parses the format produced by {@link #toBytes()} back into a {@code PqcEncryptedPayload}. */
    static PqcEncryptedPayload fromBytes(byte[] wire) {
        byte[] encapsulatedKey = Arrays.copyOfRange(wire, 0, ENCAPSULATED_KEY_LENGTH_BYTES);
        byte[] iv = Arrays.copyOfRange(
            wire, ENCAPSULATED_KEY_LENGTH_BYTES, ENCAPSULATED_KEY_LENGTH_BYTES + IV_LENGTH_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(
            wire, ENCAPSULATED_KEY_LENGTH_BYTES + IV_LENGTH_BYTES, wire.length);
        return new PqcEncryptedPayload(encapsulatedKey, iv, ciphertext);
    }

    /**
     * Records' auto-generated equals()/hashCode() compare byte[] components by reference, not by
     * content — overridden so two payloads with the same bytes compare equal (same fix already
     * applied to AesGcmEngine.EncryptedPayload, KyberKemEngine.KemResult, WrappedKeyMaterial).
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PqcEncryptedPayload other)) return false;
        return Arrays.equals(encapsulatedKey, other.encapsulatedKey)
            && Arrays.equals(iv, other.iv)
            && Arrays.equals(ciphertext, other.ciphertext);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(encapsulatedKey);
        result = 31 * result + Arrays.hashCode(iv);
        result = 31 * result + Arrays.hashCode(ciphertext);
        return result;
    }
}
