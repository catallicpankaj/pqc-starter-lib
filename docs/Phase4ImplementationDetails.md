# Phase 4 — Spring Security + JWT (Dilithium-3 Signed Tokens)

> Replace RS256/ES256 JWT signing with quantum-safe **Dilithium-3 (ML-DSA-65, FIPS 204)**.
> Plugs into the standard Spring Security filter chain with zero changes to consuming code.

---

## Why This Matters

Long-lived JWT tokens signed with RSA today are vulnerable to a **"harvest now, decrypt later"** attack:
a quantum adversary captures tokens now and breaks the RSA signature once a large quantum computer
is available. Dilithium-3 signatures eliminate this future exposure.

| Algorithm | Security Model | Quantum-Safe | Signature Size |
|-----------|---------------|-------------|----------------|
| RS256 (RSA-2048) | Factoring | No | 256 bytes |
| ES256 (ECDSA-P256) | Discrete log | No | 64 bytes |
| **DILITHIUM3** | Lattice (ML-DSA) | **Yes** | **3293 bytes** |

---

## Token Format

Structurally identical to a standard JWT — three Base64URL segments separated by `.`:

```
Base64URL(header) . Base64URL(payload) . Base64URL(signature)
```

**Header:**
```json
{ "alg": "DILITHIUM3", "typ": "JWT" }
```

**Payload (standard claims + custom):**
```json
{
  "sub": "alice",
  "iat": 1699000000,
  "exp": 1699003600,
  "roles": ["USER", "ADMIN"]
}
```

**Signature:**
```
Dilithium-3 signature over UTF-8 bytes of "header.payload"
```

Any JWT debugger (jwt.io) can decode the header and payload. Signature verification requires
the Dilithium-3 public key.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Spring Security Filter Chain                      │
│                                                                       │
│  Request → [DilithiumJwtFilter] → [Other filters] → Controller       │
│                   │                                                   │
│                   ▼                                                   │
│          Authorization: Bearer <token>                                │
│                   │                                                   │
│                   ▼                                                   │
│          DilithiumJwtService.validateToken(token)                     │
│                   │                                                   │
│          ┌────────┴────────┐                                         │
│          │                 │                                         │
│        VALID            INVALID / EXPIRED                           │
│          │                 │                                         │
│          ▼                 ▼                                         │
│   SecurityContext       401 Unauthorized                             │
│   populated             (with error reason)                          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│  com.pqc.hybrid.jwt                                          │
│                                                              │
│  ┌──────────────────────┐    ┌──────────────────────────┐   │
│  │  DilithiumJwtService │───▶│  DilithiumKeyPairHolder  │   │
│  │                      │    │                          │   │
│  │  issueToken()        │    │  getSigningKeyPair()     │   │
│  │  validateToken()     │    │                          │   │
│  └──────────────────────┘    │  Phase 3 present:        │   │
│            ▲                 │    QuantumKeyService      │   │
│            │                 │    (KMS-managed key)      │   │
│  ┌─────────────────────┐     │  Phase 3 absent:          │   │
│  │ DilithiumJwtFilter  │     │    ephemeral in-memory    │   │
│  │ (OncePerRequestFilter)    └──────────────────────────┘   │
│  │                      │              │                    │
│  │ reads Bearer token   │              ▼                    │
│  │ calls validateToken()│    ┌──────────────────────────┐   │
│  │ sets SecurityContext │    │  DilithiumSigningEngine   │   │
│  └─────────────────────┘    │  (Phase 1, already built) │   │
│            ▲                 └──────────────────────────┘   │
│            │                                                 │
│  ┌─────────────────────────┐                                │
│  │ DilithiumJwtAuthCtrl    │                                │
│  │                         │                                │
│  │ POST /auth/token        │                                │
│  │   → issues JWT          │                                │
│  │ GET  /api/secure        │                                │
│  │   → protected resource  │                                │
│  └─────────────────────────┘                                │
└─────────────────────────────────────────────────────────────┘
```

---

## Sequence Diagram — Token Issuance

```
Client                    DilithiumJwtAuthController      DilithiumJwtService      DilithiumKeyPairHolder
  │                               │                              │                        │
  │  POST /auth/token             │                              │                        │
  │  {"username":"alice",         │                              │                        │
  │   "password":"secret"}        │                              │                        │
  │──────────────────────────────▶│                              │                        │
  │                               │  issueToken(sub, roles, ttl) │                        │
  │                               │─────────────────────────────▶│                        │
  │                               │                              │  getSigningKeyPair()   │
  │                               │                              │───────────────────────▶│
  │                               │                              │◀───────────────────────│
  │                               │                              │  KeyPair               │
  │                               │                              │                        │
  │                               │                              │  Build header.payload  │
  │                               │                              │  DilithiumSign(privKey) │
  │                               │                              │  Base64URL encode      │
  │                               │◀─────────────────────────────│                        │
  │                               │  "header.payload.signature"  │                        │
  │◀──────────────────────────────│                              │                        │
  │  200 OK {"token":"..."}       │                              │                        │
```

---

## Sequence Diagram — Token Validation (per request)

```
Client                  DilithiumJwtFilter           DilithiumJwtService      DilithiumSigningEngine
  │                           │                             │                        │
  │  GET /api/secure          │                             │                        │
  │  Authorization: Bearer T  │                             │                        │
  │──────────────────────────▶│                             │                        │
  │                           │  validateToken(T)           │                        │
  │                           │────────────────────────────▶│                        │
  │                           │                             │  Split header.payload.sig
  │                           │                             │  Decode header → alg check
  │                           │                             │  Decode payload → exp check
  │                           │                             │  verify(pubKey, h.p, sig) │
  │                           │                             │───────────────────────────▶
  │                           │                             │◀───────────────────────────
  │                           │                             │  true / false              │
  │                           │◀────────────────────────────│                        │
  │                           │  DilithiumJwt{sub, roles}   │                        │
  │                           │                             │                        │
  │                           │  SecurityContextHolder      │                        │
  │                           │  .setAuthentication(...)    │                        │
  │                           │                             │                        │
  │◀──────────────────────────│                             │                        │
  │  200 OK (protected data)  │                             │                        │
```

---

## Phase 3 Integration

`DilithiumKeyPairHolder` follows the same `Optional<QuantumKeyService>` pattern as
`HybridHandshakeOrchestrator`:

```
QuantumKeyService present  →  Dilithium signing keypair managed by KMS
                               persists across restarts, rotates on schedule
QuantumKeyService absent   →  Ephemeral in-memory keypair (Phase 1/2 compat)
                               new key on every restart, no KMS required
```

`QuantumKeyService` gains a third managed key:

| Key ID | Algorithm | Purpose |
|--------|-----------|---------|
| `kyber-server-key` | Kyber-768 | Key encapsulation (handshake) |
| `ec-server-key` | EC-P384 | ECDHE (handshake, hybrid mode) |
| `dilithium-signing-key` | Dilithium-3 | JWT signing + verification |

---

## New Files

```
src/main/java/com/pqc/hybrid/jwt/
├── DilithiumJwt.java                  — Record: parsed token value object
├── DilithiumJwtException.java         — Typed exception: EXPIRED / INVALID_SIGNATURE / MALFORMED
├── DilithiumKeyPairHolder.java        — Manages signing keypair (KMS or ephemeral)
├── DilithiumJwtService.java           — issueToken() + validateToken()
├── DilithiumJwtFilter.java            — OncePerRequestFilter for Spring Security
└── DilithiumJwtAuthController.java    — Demo: POST /auth/token, GET /api/secure
```

---

## Modified Files

| File | Change |
|------|--------|
| `QuantumKeyService.java` | Add `KEY_DILITHIUM`, `getActiveDilithiumKeyPair()`, bootstrap Dilithium key |
| `SecurityConfig.java` | Register `DilithiumJwtFilter`, permit `/auth/**` |
| `PqcAutoConfiguration.java` | Register `DilithiumKeyPairHolder`, `DilithiumJwtService`, `DilithiumJwtFilter` beans |

---

## No New Maven Dependencies

BouncyCastle (Dilithium already implemented in Phase 1), Spring Security, and Jackson
(included via `spring-boot-starter-web`) are sufficient.

---

## REST API

### Issue Token

```
POST /auth/token
Content-Type: application/json

{ "username": "alice", "password": "secret" }
```

Response:
```json
{
  "token": "eyJhbGciOiJESUxJVEhJVU0zIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSIsImlhdCI6MTY5OTAwMDAwMCwiZXhwIjoxNjk5MDAzNjAwLCJyb2xlcyI6WyJVU0VSIl19.<dilithium-sig>",
  "expiresInSeconds": 3600,
  "algorithm": "DILITHIUM3"
}
```

### Access Protected Resource

```
GET /api/secure
Authorization: Bearer <token>
```

Response (200 OK):
```json
{
  "message": "Hello alice — you are authenticated with a quantum-safe Dilithium-3 JWT",
  "subject": "alice",
  "roles": ["USER"],
  "algorithm": "DILITHIUM3",
  "quantumSafe": true
}
```

### Access Without Token

```
GET /api/secure
```

Response (401 Unauthorized):
```json
{
  "error": "Missing or invalid Authorization header"
}
```

---

## application.yml Configuration

```yaml
pqc:
  jwt:
    enabled: true              # set false to disable JWT endpoints (default: true)
    ttl-minutes: 60            # token lifetime (default: 60)
    demo-password: secret      # demo login password (NOT for production)
```

---

## Test Coverage (`DilithiumJwtTest.java`)

| Test | What It Verifies |
|------|-----------------|
| `issueAndValidateRoundTrip` | Token issued and validated with correct subject + roles |
| `expiredTokenRejected` | Token with past expiry throws EXPIRED |
| `tamperedPayloadRejected` | Modified payload fails signature check |
| `tamperedSignatureRejected` | Corrupted signature bytes fail Dilithium verify |
| `wrongPublicKeyRejected` | Different keypair cannot validate a token |
| `malformedTokenRejected` | Non-JWT string throws MALFORMED |
| `missingSegmentsRejected` | Only one or two segments throws MALFORMED |
| `rolesRoundTrip` | Multi-role list serialised and deserialised correctly |
| `filterAllowsValidToken` | MockMvc: 200 on /api/secure with valid token |
| `filterBlocks401WithoutToken` | MockMvc: 401 on /api/secure with no token |
| `filterBlocks401WithExpiredToken` | MockMvc: 401 on /api/secure with expired token |

---

## Key Rotation Impact

When Phase 3 rotates the `dilithium-signing-key`:
- New tokens are signed with V2 (new private key)
- Existing tokens signed with V1 can still be validated via `getUsableForDecryption()` (deprecated but not retired)
- After the deprecation window, V1 is retired — old tokens become invalid (expected behaviour)

This mirrors how OAuth2 providers rotate signing keys: the JWKS endpoint serves multiple public keys,
and tokens include a `kid` (key ID) claim to tell the validator which key to use. A future enhancement
can add `kid` to the JWT header pointing to the `KeyVersion.version`.
