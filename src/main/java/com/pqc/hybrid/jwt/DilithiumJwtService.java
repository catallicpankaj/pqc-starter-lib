package com.pqc.hybrid.jwt;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Issues and validates Dilithium-3 signed JWT tokens.
 *
 * TOKEN FORMAT (structurally a JWT, non-standard algorithm identifier):
 * ┌──────────────────┬───────────────────────────┬───────────────────────────────────┐
 * │  Header          │  Payload                  │  Signature                        │
 * │  Base64URL(JSON) │  Base64URL(JSON)           │  Base64URL(Dilithium-3 sig bytes) │
 * └──────────────────┴───────────────────────────┴───────────────────────────────────┘
 *
 * Header JSON:  {"alg":"DILITHIUM3","typ":"JWT"}
 * Payload JSON: {"sub":"user","iat":1699...,"exp":1699...,"roles":["USER"]}
 *
 * The Dilithium-3 signature is computed over the UTF-8 bytes of "header.payload"
 * (the first two Base64URL segments joined by a dot — identical to standard JWT).
 *
 * No external JWT library is required. BouncyCastle provides the Dilithium-3
 * primitive and Jackson (already in Spring Boot) handles JSON.
 */
public class DilithiumJwtService {

    private static final Logger log = LoggerFactory.getLogger(DilithiumJwtService.class);

    public static final  String ALG_HEADER  = "DILITHIUM3";
    private static final String BCPQC       = "BCPQC";
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DEC = Base64.getUrlDecoder();

    private final DilithiumKeyPairHolder keyHolder;
    private final ObjectMapper           mapper;
    private final long                   ttlSeconds;

    static {
        if (Security.getProvider(BCPQC) == null) {
            Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);
        }
    }

    /**
     * @param keyHolder   Holds the Dilithium-3 signing keypair (KMS or ephemeral).
     * @param mapper      Jackson ObjectMapper (provided by Spring Boot auto-config).
     * @param ttlMinutes  Token lifetime in minutes (e.g. 60).
     */
    public DilithiumJwtService(DilithiumKeyPairHolder keyHolder,
                                ObjectMapper mapper,
                                long ttlMinutes) {
        this.keyHolder  = keyHolder;
        this.mapper     = mapper;
        this.ttlSeconds = ttlMinutes * 60L;
    }

    // ─────────────────────────────────────────────────────────────
    // Token issuance
    // ─────────────────────────────────────────────────────────────

    /**
     * Issues a Dilithium-3 signed JWT token.
     *
     * @param subject  The "sub" claim — typically the authenticated username.
     * @param roles    List of role strings to embed in the "roles" claim.
     * @return         Signed JWT token string: "header.payload.signature"
     */
    public String issueToken(String subject, List<String> roles) throws Exception {
        Instant now    = Instant.now();
        Instant expiry = now.plusSeconds(ttlSeconds);

        // Build header
        Map<String, String> header = new LinkedHashMap<>();
        header.put("alg", ALG_HEADER);
        header.put("typ", "JWT");

        // Build payload
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("sub",   subject);
        payload.put("iat",   now.getEpochSecond());
        payload.put("exp",   expiry.getEpochSecond());
        payload.put("roles", roles);

        String encodedHeader  = B64.encodeToString(mapper.writeValueAsBytes(header));
        String encodedPayload = B64.encodeToString(mapper.writeValueAsBytes(payload));
        String signingInput   = encodedHeader + "." + encodedPayload;

        // Sign with Dilithium-3
        byte[] sigBytes = dilithiumSign(signingInput.getBytes(StandardCharsets.UTF_8));
        String encodedSig = B64.encodeToString(sigBytes);

        String token = signingInput + "." + encodedSig;
        log.debug("Issued Dilithium-3 JWT for sub={} exp={} sigBytes={}B", subject, expiry, sigBytes.length);
        return token;
    }

    // ─────────────────────────────────────────────────────────────
    // Token validation
    // ─────────────────────────────────────────────────────────────

    /**
     * Validates a Dilithium-3 signed JWT token.
     *
     * Checks (in order):
     *   1. Structural validity — exactly three Base64URL segments
     *   2. Header "alg" field is "DILITHIUM3"
     *   3. Dilithium-3 signature over "header.payload" is valid
     *   4. "exp" claim is in the future
     *
     * @param token  JWT token string.
     * @return       Parsed {@link DilithiumJwt} with subject, roles, timestamps.
     * @throws DilithiumJwtException  if the token is invalid for any reason.
     */
    public DilithiumJwt validateToken(String token) {
        // 1. Split segments
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new DilithiumJwtException(
                DilithiumJwtException.Reason.MALFORMED,
                "JWT must have exactly 3 segments, found: " + parts.length);
        }

        String encodedHeader  = parts[0];
        String encodedPayload = parts[1];
        String encodedSig     = parts[2];

        Map<String, Object> headerMap;
        Map<String, Object> payloadMap;
        byte[] sigBytes;

        try {
            headerMap  = mapper.readValue(DEC.decode(encodedHeader),
                             new TypeReference<Map<String, Object>>() {});
            payloadMap = mapper.readValue(DEC.decode(encodedPayload),
                             new TypeReference<Map<String, Object>>() {});
            sigBytes   = DEC.decode(encodedSig);
        } catch (Exception e) {
            throw new DilithiumJwtException(
                DilithiumJwtException.Reason.MALFORMED,
                "Failed to decode JWT segments: " + e.getMessage(), e);
        }

        // 2. Algorithm check
        String alg = String.valueOf(headerMap.get("alg"));
        if (!ALG_HEADER.equals(alg)) {
            throw new DilithiumJwtException(
                DilithiumJwtException.Reason.MALFORMED,
                "Unsupported algorithm: " + alg + " (expected " + ALG_HEADER + ")");
        }

        // 3. Signature verification
        String signingInput = encodedHeader + "." + encodedPayload;
        boolean valid;
        try {
            valid = dilithiumVerify(signingInput.getBytes(StandardCharsets.UTF_8), sigBytes);
        } catch (Exception e) {
            throw new DilithiumJwtException(
                DilithiumJwtException.Reason.INVALID_SIGNATURE,
                "Signature verification error: " + e.getMessage(), e);
        }
        if (!valid) {
            throw new DilithiumJwtException(
                DilithiumJwtException.Reason.INVALID_SIGNATURE,
                "Dilithium-3 signature verification failed");
        }

        // 4. Expiry check (after signature — don't reveal expiry of tampered tokens)
        long expEpoch = ((Number) payloadMap.get("exp")).longValue();
        Instant expiresAt = Instant.ofEpochSecond(expEpoch);
        if (Instant.now().isAfter(expiresAt)) {
            throw new DilithiumJwtException(
                DilithiumJwtException.Reason.EXPIRED,
                "JWT expired at " + expiresAt);
        }

        long iatEpoch = ((Number) payloadMap.get("iat")).longValue();
        String subject = String.valueOf(payloadMap.get("sub"));

        @SuppressWarnings("unchecked")
        List<String> roles = payloadMap.get("roles") instanceof List
            ? (List<String>) payloadMap.get("roles")
            : List.of();

        log.debug("Validated Dilithium-3 JWT for sub={}", subject);
        return new DilithiumJwt(subject, roles, Instant.ofEpochSecond(iatEpoch), expiresAt, ALG_HEADER);
    }

    /** Returns the token lifetime in seconds (for issuing expiry headers). */
    public long getTtlSeconds() { return ttlSeconds; }

    // ─────────────────────────────────────────────────────────────
    // Dilithium-3 primitives
    // ─────────────────────────────────────────────────────────────

    private byte[] dilithiumSign(byte[] data) throws Exception {
        Signature signer = Signature.getInstance("Dilithium", BCPQC);
        signer.initSign(keyHolder.getPrivateKey());
        signer.update(data);
        return signer.sign();
    }

    private boolean dilithiumVerify(byte[] data, byte[] signature) throws Exception {
        Signature verifier = Signature.getInstance("Dilithium", BCPQC);
        verifier.initVerify(keyHolder.getPublicKey());
        verifier.update(data);
        return verifier.verify(signature);
    }
}
