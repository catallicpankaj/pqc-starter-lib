package com.pqc.hybrid.jwt;

import java.time.Instant;
import java.util.List;

/**
 * Parsed, validated Dilithium-signed JWT token.
 *
 * Returned by {@link DilithiumJwtService#validateToken(String)} when the token
 * is structurally correct, the Dilithium-3 signature is valid, and the token
 * has not expired.
 *
 * @param subject    The "sub" claim — typically the authenticated username.
 * @param roles      The "roles" claim — list of role strings (e.g. ["USER", "ADMIN"]).
 * @param issuedAt   When the token was issued.
 * @param expiresAt  When the token expires.
 * @param algorithm  The signing algorithm identifier (always "DILITHIUM3").
 */
public record DilithiumJwt(
        String        subject,
        List<String>  roles,
        Instant       issuedAt,
        Instant       expiresAt,
        String        algorithm
) {
    /** Convenience — returns true if this token is still within its validity window. */
    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }
}
