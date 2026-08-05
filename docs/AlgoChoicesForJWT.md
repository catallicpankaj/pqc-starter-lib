# Algorithm Choices for JWT Signing — Why Dilithium-3?

> Explains why Dilithium-3 is the correct algorithm for JWT token signing,
> and why Kyber-768 and SPHINCS+ are not used for this purpose.

---

## The Question

PqcStarterLib implements three post-quantum algorithms: Kyber-768, Dilithium-3, and SPHINCS+.
When generating JWT tokens, only Dilithium-3 is used. Why not Kyber or SPHINCS+?

---

## Kyber-768 — Cannot Sign, By Design

Kyber is a **Key Encapsulation Mechanism (KEM)**. Its mathematical construction produces
a shared secret from a ciphertext — there is no concept of "sign this data" in its design.

The analogy to classical cryptography:

```
RSA Encrypt   ≈  Kyber encapsulate    (establish a shared secret)
RSA Sign      ≈  Dilithium sign       (authenticate a message)
```

Kyber is used in PqcStarterLib's hybrid handshake to establish session keys between
a client and server. It cannot be used to sign a JWT payload — it simply does not
have a signing operation.

**Role in PqcStarterLib:** Key exchange (Phase 1 handshake, Phase 3 key management)
**Role in JWT:** None — wrong primitive

---

## SPHINCS+ — Could Sign, But Wrong Trade-Off for JWTs

SPHINCS+ (SLH-DSA, FIPS 205) is a valid post-quantum **digital signature algorithm**,
so it is technically capable of signing JWT tokens. However, it is designed for a
very different use case.

### Performance comparison

| Property | Dilithium-3 (ML-DSA-65) | SPHINCS+-SHA2-128f (SLH-DSA) |
|----------|------------------------|------------------------------|
| Signature size | ~3,293 bytes | ~17,088 bytes |
| Sign speed | ~1–2 ms | ~30–100 ms |
| Verify speed | ~0.5–1 ms | ~2–5 ms |
| Security basis | Lattice (Module LWE) | Hash function (SHA-2) |
| NIST standard | FIPS 204 | FIPS 205 |

### Why SPHINCS+ size matters for JWTs

A SPHINCS+ signed JWT would be **~17 KB per token**. Every HTTP request carrying a
Bearer token would send ~17 KB in the Authorization header. For a service handling
1,000 requests/second, that is 17 MB/s of token data alone on the wire — before any
actual request payload.

### What SPHINCS+ is designed for

SPHINCS+ is optimised for scenarios where:
- Signatures are **rare** (not per-request)
- Signatures must remain valid for **decades** (root CA certificates, legal documents)
- You want security based entirely on **hash functions** rather than lattice problems
  (maximum conservatism — if lattice assumptions are ever broken, SPHINCS+ is unaffected)

Ideal SPHINCS+ use cases in PqcStarterLib's roadmap:
- Root CA certificates (Phase 7 — TLS layer)
- Code signing
- Long-lived document signatures
- Firmware signing

**Role in PqcStarterLib:** Long-term / infrequent signing (signing engine available, Phase 7 integration planned)
**Role in JWT:** Not suitable — 5× larger signature, 30–50× slower signing

---

## Dilithium-3 — The Correct Choice

Dilithium-3 (ML-DSA-65, FIPS 204) is the NIST-standardised post-quantum digital signature
algorithm optimised for **general-purpose, high-frequency signing**. It is the direct
quantum-safe replacement for RS256/ES256 in JWT tokens.

### Why it fits

- **Size:** ~3.3 KB signature is bearable in an HTTP Authorization header
- **Speed:** ~1–2 ms signing latency — acceptable for per-request authentication
- **Standard:** FIPS 204, published August 2024 — production-ready
- **Security:** Based on Module Learning With Errors (MLWE) — a well-studied lattice problem
- **Drop-in:** Same sign/verify interface as ECDSA — easy to slot into JWT infrastructure

### Comparison with classical JWT algorithms

| Algorithm | Type | Quantum-Safe | Signature Size |
|-----------|------|-------------|----------------|
| HS256 | HMAC-SHA256 | No (Grover: ~128-bit) | 32 bytes |
| RS256 | RSA-2048 | **No** (Shor) | 256 bytes |
| ES256 | ECDSA-P256 | **No** (Shor) | 64 bytes |
| **DILITHIUM3** | **ML-DSA-65** | **Yes** | **~3,293 bytes** |

The size increase from ES256 (64 bytes) to Dilithium-3 (~3,293 bytes) is the cost of
quantum safety. This is a known and accepted trade-off in post-quantum cryptography.

---

## Summary

```
Algorithm    │  Can Sign?  │  Suitable for JWT?  │  Why / Why Not
─────────────┼─────────────┼─────────────────────┼──────────────────────────────────────
Kyber-768    │  No         │  No                 │  KEM only — no signing operation
Dilithium-3  │  Yes        │  ✓ Yes              │  Fast, reasonably sized, FIPS 204
SPHINCS+     │  Yes        │  No (for now)       │  5× larger, 50× slower — for rare/long-lived sigs
```

**If you need belt-and-suspenders security** (two independent mathematical assumptions),
you could sign with both Dilithium-3 AND SPHINCS+ and embed both signatures in the token.
The token would be ~20 KB per request — impractical for most web APIs, but defensible
for very high-security, low-frequency token issuance scenarios.

---

## Where SPHINCS+ Will Be Used

Phase 7 (TLS Layer) will use SPHINCS+ for **Dilithium X.509 certificates**:
- The CA root certificate is signed with SPHINCS+ (long-lived, hash-based security)
- The server's leaf certificate is signed with Dilithium-3 (shorter-lived, faster)
- This mirrors the classical PKI pattern: RSA root CA signing ECDSA leaf certs
