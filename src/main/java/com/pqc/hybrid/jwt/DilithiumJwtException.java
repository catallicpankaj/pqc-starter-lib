package com.pqc.hybrid.jwt;

/**
 * Thrown by {@link DilithiumJwtService#validateToken(String)} when a token
 * cannot be accepted. The {@link Reason} enum distinguishes the failure mode
 * so callers can return appropriate HTTP responses.
 */
public class DilithiumJwtException extends RuntimeException {

    public enum Reason {
        /** Token's "exp" claim is in the past. */
        EXPIRED,
        /** Dilithium-3 signature verification failed — token was tampered with. */
        INVALID_SIGNATURE,
        /** Token string is not a valid three-segment Base64URL JWT. */
        MALFORMED
    }

    private final Reason reason;

    public DilithiumJwtException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public DilithiumJwtException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public Reason getReason() {
        return reason;
    }
}
