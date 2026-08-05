# Phase 1 — Core Cryptography Engine: Implementation Guide

> Real, non-simulated post-quantum primitives — Kyber-768 (ML-KEM), Dilithium-3 (ML-DSA),
> SPHINCS+ (SLH-DSA) — plus the hybrid classical+PQC key derivation that is this project's
> core contribution. No Spring, no HTTP — just bytes in, bytes out.

---

## Scope

Phase 1 is the cryptographic engine underneath everything else in this library. It has no
dependency on Spring, HTTP, or any of the later phases — it is plain Java + BouncyCastle. Phase 2
wraps these primitives into Spring-injectable beans; Phases 3–6 build KMS, JWT, migration, and
at-rest tooling on top. None of that exists without Phase 1.

**What's in scope:** key encapsulation (Kyber), digital signatures (Dilithium, SPHINCS+), classical
key agreement (ECDHE), and the hybrid key-derivation function that combines classical and PQC
secrets into one session key.

**What's explicitly out of scope:** Spring wiring (Phase 2), persistent keys (Phase 3), JWT
issuance (Phase 4) — Phase 1 only produces raw key material and signatures in memory.

---

## Architecture Overview

```
┌───────────────────────────────────────────────────────────────────────┐
│  HybridHandshakeOrchestrator                                          │
│  Runtime mode selection + the hybrid KDF (the novel contribution)     │
│                                                                        │
│   orchestrate(ClientCapability) ──► negotiateBestMode() ──► one of:   │
│     performHybridHandshake()    — ECDHE + Kyber, combined via KDF     │
│     performPqcHandshake()       — Kyber only                         │
│     performClassicalHandshake() — ECDHE only                         │
└───────────────┬───────────────────────────────────┬───────────────────┘
                │                                   │
                ▼                                   ▼
   ┌─────────────────────────┐         ┌─────────────────────────────┐
   │  KyberKemEngine          │         │  java.security (JCA/BC)      │
   │  generateKeyPair()       │         │  ECDH KeyAgreement            │
   │  encapsulate(pubKey)     │         │  KeyPairGenerator("EC")       │
   │  decapsulate(privKey,ct) │         │  secp384r1 (P-384)            │
   └─────────────────────────┘         └─────────────────────────────┘

┌───────────────────────────────────────────────────────────────────────┐
│  DilithiumSigningEngine          │  SphincsSigningEngine               │
│  generateKeyPair() / sign() / verify()  (both — same shape, different │
│  algorithm underneath)                                                │
└───────────────────────────────────────────────────────────────────────┘
```

### Design Patterns Used

| Pattern | Where | Why |
|---|---|---|
| **Strategy (implicit)** | `CipherMode` enum + `switch` in `orchestrate()` | Three interchangeable handshake algorithms behind one entry point |
| **Builder** | `ClientCapability.Builder`, `HandshakeSession.Builder` | Immutable value objects with several optional fields |
| **Record (DTO)** | `KyberKemEngine.KemResult`, `HandshakeSession.SessionSummary` | Immutable, no-boilerplate carriers for KEM output and safe session metadata |
| **Safe accessor** | `HandshakeSession.toSummary()` | Never expose raw key material outside the class — only a truncated fingerprint |

---

## Package Structure

```
com.pqc.hybrid.handshake/
├── CipherMode.java                 ← CLASSICAL / PQC_ONLY / HYBRID enum
├── ClientCapability.java           ← what a connecting client advertises + negotiateBestMode()
├── HandshakeSession.java           ← result of a completed handshake (session key + metadata)
├── KyberKemEngine.java             ← Kyber-768 encapsulate / decapsulate
└── HybridHandshakeOrchestrator.java ← runtime mode selection + hybrid KDF (the core engine)

com.pqc.hybrid.signing/
├── DilithiumSigningEngine.java     ← Dilithium-3 (ML-DSA-65) sign / verify
└── SphincsSigningEngine.java       ← SPHINCS+-SHA2-128f (SLH-DSA) sign / verify
```

All six classes are plain Java — `HybridHandshakeOrchestrator` is `@Component`-annotated and the
signing engines are `@Component`-annotated for Spring pickup, but none of them import anything
from `org.springframework.web` or `org.springframework.http`. They can be unit tested (and are)
with zero Spring context.

---

## Kyber-768 Key Encapsulation (`KyberKemEngine`)

Kyber is a **Key Encapsulation Mechanism (KEM)**, not a general-purpose encryption algorithm — it
establishes a shared secret between two parties who hold a key pair, it does not encrypt arbitrary
data directly. `KyberKemEngine` wraps three JCA calls against BouncyCastle's `BCPQC` provider:

```java
KeyPairGenerator.getInstance("Kyber", "BCPQC").initialize(KyberParameterSpec.kyber768);
KeyGenerator.getInstance("Kyber", "BCPQC").init(new KEMGenerateSpec(serverPublicKey, "AES"));  // encapsulate
KeyGenerator.getInstance("Kyber", "BCPQC").init(new KEMExtractSpec(serverPrivateKey, ciphertext, "AES")); // decapsulate
```

### Encapsulation / Decapsulation Sequence

```
  Caller                 KyberKemEngine
    │                          │
    │  encapsulate(serverPublicKey)
    │─────────────────────────►│
    │                          │──┐  KeyGenerator("Kyber", BCPQC)
    │                          │  │  .init(KEMGenerateSpec(pubKey, "AES"))
    │                          │  │  .generateKey() → SecretKeyWithEncapsulation
    │                          │◄─┘
    │  KemResult(              │
    │    sharedSecret: 32B,    │
    │    ciphertext:  1088B)   │
    │◄─────────────────────────│
    │                          │
    │  [caller sends ciphertext over the wire — sharedSecret stays local]
    │                          │
    │  decapsulate(serverPrivateKey, ciphertext)
    │─────────────────────────►│
    │                          │──┐  KeyGenerator("Kyber", BCPQC)
    │                          │  │  .init(KEMExtractSpec(privKey, ct, "AES"))
    │                          │  │  .generateKey() → same 32-byte secret
    │                          │◄─┘
    │  sharedSecret: 32B       │
    │  (identical to encap's)  │
    │◄─────────────────────────│
```

`HybridHandshakeOrchestrator.performHybridHandshake()` calls both sides **in the same method** —
it encapsulates to the server's own Kyber public key, then immediately decapsulates with the
server's own private key, to prove the round trip produces the same secret. This is intentional:
Phase 1/2 demonstrate the cryptography with both "sides" simulated in one JVM. In a real
multi-service deployment, the ciphertext would cross the network — the client keeps `sharedSecret`
locally and sends only `ciphertext`; nobody except the private-key holder can recover the same
secret from it.

### Measured Sizes (this repo's test suite, BouncyCastle 1.78.1, JDK 17)

| Field | Measured (Java-encoded) | NIST FIPS 203 raw wire size | Why they differ |
|---|---|---|---|
| Public key | 1208 bytes | 1184 bytes | Java wraps it in an X.509 `SubjectPublicKeyInfo` (ASN.1 header overhead) |
| Private key | 2430 bytes | 2400 bytes | Java wraps it in a PKCS#8 `PrivateKeyInfo` |
| Ciphertext (ct) | 1088 bytes | 1088 bytes | No wrapping — this is the raw KEM ciphertext |
| Shared secret | 32 bytes | 32 bytes | Fixed by the KEM |

If you serialize keys with `.getEncoded()` (as this library does internally) you get the
Java-encoded sizes. If you're comparing against the NIST spec or another implementation's raw byte
counts, expect the ASN.1-wrapped sizes to run ~24 bytes larger.

**Verified security property (IND-CCA2):** decapsulating a valid ciphertext with the *wrong*
private key does not throw — Kyber's implicit-rejection design returns a value that is
indistinguishable from a random secret, rather than an error, so an attacker probing for the
"wrong key" signal learns nothing. `KyberKemEngineTest.wrongPrivateKeyFails()` asserts exactly
this: the wrong-key output differs from the real shared secret, with no exception thrown either way.

---

## The Hybrid Handshake (`HybridHandshakeOrchestrator`) — Core Contribution

Three modes, selected per-client at runtime by `ClientCapability.negotiateBestMode()`:

```java
public CipherMode negotiateBestMode() {
    if (!pqcCapable) return CipherMode.CLASSICAL;
    if (hybridCapable && (supports("Kyber-768") || supports("ML-KEM-768"))) return CipherMode.HYBRID;
    if (pqcCapable) return CipherMode.PQC_ONLY;
    return CipherMode.CLASSICAL;
}
```

```
CLASSICAL:  SessionKey = HMAC-SHA256(ECDHE_secret,                 session_id)
PQC_ONLY:   SessionKey = HMAC-SHA256(Kyber_secret,                  session_id)
HYBRID:     SessionKey = HMAC-SHA256(ECDHE_secret || Kyber_secret,  session_id)
```

The HYBRID formula is the actual code in `hybridKdf()`:

```java
private byte[] hybridKdf(byte[] classicalSecret, byte[] kyberSecret, String sessionId) throws Exception {
    Mac hmac = Mac.getInstance("HmacSHA256", "BC");
    hmac.init(new SecretKeySpec(sessionId.getBytes(), "HmacSHA256"));
    hmac.update(classicalSecret);
    hmac.update(kyberSecret);
    return hmac.doFinal();
}
```

Using the session ID as the HMAC key (rather than as data being hashed) means two different
sessions built from the *same* pair of classical/PQC secrets would still derive *different* session
keys — an accidental defense against secret reuse across sessions. **An attacker must break both
ECDHE-P384 and Kyber-768 to recover the HYBRID session key** — compromising only one algorithm
leaves the key computationally unrecoverable.

> **Note on `hybridKdf`:** the code comment above `hybridKdf()` flags this directly — in a
> production hardening pass this should be replaced with a proper HKDF-Extract-and-Expand (RFC
> 5869), which `HkdfKeyDerivation` (used by Phase 6's at-rest module) already implements elsewhere
> in this codebase. The HMAC-based construction used here is cryptographically sound but not a
> textbook KDF.

### Full HYBRID Handshake Sequence

```
  Caller           HybridHandshakeOrchestrator      KyberKemEngine        JCA (BC provider)
    │                       │                             │                      │
    │  orchestrate(capability)                             │                      │
    │──────────────────────►│                              │                      │
    │                       │  negotiateBestMode() → HYBRID│                      │
    │                       │                              │                      │
    │                       │──┐ generateEcKeyPair()        │                      │
    │                       │  │ (client-side ephemeral)     │                      │
    │                       │  │────────────────────────────────────────────────► │
    │                       │  │◄──────────────────────────────────────────────── │
    │                       │◄─┘ EC KeyPair (secp384r1)     │                      │
    │                       │                              │                      │
    │                       │──┐ ecdhKeyAgreement(          │                      │
    │                       │  │   clientEcPair,             │                      │
    │                       │  │   serverEcKeyPair)          │                      │
    │                       │  │────────────────────────────────────────────────► │
    │                       │  │◄──────────────────────────────────────────────── │
    │                       │◄─┘ classicalSecret (48B)      │                      │
    │                       │                              │                      │
    │                       │  encapsulate(serverKyberPub)  │                      │
    │                       │─────────────────────────────►│                      │
    │                       │◄─────── KemResult(secret=32B, ct=1088B) ────────────│
    │                       │                              │                      │
    │                       │  decapsulate(serverKyberPriv, ct)                   │
    │                       │─────────────────────────────►│                      │
    │                       │◄─────── serverKyberSecret (32B, == kem.sharedSecret)│
    │                       │                              │                      │
    │                       │──┐ hybridKdf(classicalSecret, │                      │
    │                       │  │   kem.sharedSecret,          │                      │
    │                       │  │   sessionId)                 │                      │
    │                       │  │   HMAC-SHA256               │                      │
    │                       │◄─┘ hybridKey (32B)             │                      │
    │                       │                              │                      │
    │  HandshakeSession(    │                              │                      │
    │    HYBRID, hybridKey, │                              │                      │
    │    quantumSafe=true)  │                              │                      │
    │◄──────────────────────│                              │                      │
```

`performPqcHandshake()` and `performClassicalHandshake()` follow the same shape with one leg
removed and `simpleKdf()` (a single-secret HMAC) instead of `hybridKdf()`.

### Session Caching and Upgrade

`HybridHandshakeOrchestrator` keeps a `ConcurrentHashMap<String, HandshakeSession>` of every
session it has negotiated. `upgradeSession(existingSessionId, newCapability)` looks up the old
session, negotiates the new capability's mode, and — **only if the new mode is strictly stronger**
(`CipherMode` ordinal comparison: `CLASSICAL < PQC_ONLY < HYBRID`) — replaces the cached session
in place under the same session ID. This lets a client that connected as `CLASSICAL` and later
advertises PQC support get upgraded to `HYBRID` without reconnecting or losing its session
identity. Downgrades are silently ignored (`current` mode is kept).

`HandshakeSession.getSessionKeyMaterial()` returns a **defensive copy** (`Arrays.copyOf`) of the
key bytes on every call — the internal array is never returned by reference, so callers cannot
mutate the cached session's key.

---

## Digital Signatures — Dilithium-3 and SPHINCS+

Both engines expose the same four-method shape (`generateKeyPair`, `sign`, `verify`, plus
`signString`/`verifyString` convenience overloads) against different BouncyCastle algorithms —
`"Dilithium"` / `DilithiumParameterSpec.dilithium3` vs. `"SPHINCSPlus"` /
`SPHINCSPlusParameterSpec.sha2_128f`. Sign/verify is a direct JCA `Signature` call:

```java
Signature signer = Signature.getInstance("Dilithium", "BCPQC");
signer.initSign(privateKey);
signer.update(data);
byte[] signature = signer.sign();
```

### Measured Sizes and Performance (this repo's test suite)

| Algorithm | Public key | Private key | Signature | Sign+verify time |
|---|---|---|---|---|
| Dilithium-3 (ML-DSA-65) | 1976 B | 6019 B | ~3309 B | ~1–2 ms |
| SPHINCS+-SHA2-128f (SLH-DSA) | 47 B | 118 B | 17088 B | ~25–30 ms (sign alone) |

Numbers above are measured directly from `PqcSigningEnginesTest` on commodity hardware (JDK 17,
BouncyCastle 1.78.1) — **actual timings vary by hardware and JIT warm-up state; treat these as
ballpark, not a guaranteed SLA.** The relative shape is the important part and is stable across
runs:

- **Dilithium** has larger keys but a much smaller signature and signs an order of magnitude
  faster — the right default for anything signed frequently (JWTs, per-request message auth).
  This is exactly why Phase 4's JWT signing uses Dilithium-3 and not SPHINCS+ — see
  [`AlgoChoicesForJWT.md`](AlgoChoicesForJWT.md) for the full comparison including Kyber, which
  is excluded because a KEM cannot sign at all.
- **SPHINCS+** has a tiny public key (47 bytes — smaller than a Dilithium signature's rounding
  error) but a huge signature (17 KB) and signs much slower. Its security rests only on hash
  function collision resistance — the most conservative assumption among the three NIST PQC
  families — making it the right choice for long-lived, infrequently-issued signatures: CA root
  certificates, code-signing keys, archival document signatures that must remain verifiable
  decades from now.

Both engines reject tampering and wrong-key verification correctly — `PqcSigningEnginesTest`
covers tampered-message rejection and cross-keypair rejection for both algorithms explicitly.

---

## Test Coverage

| Test class | What it covers |
|---|---|
| `KyberKemEngineTest` (5 tests) | Key pair sizes, encap/decap round-trip, uniqueness per call, wrong-key IND-CCA2 behavior, performance |
| `PqcSigningEnginesTest` (10 tests) | Dilithium key sizes/sign/verify/tamper/wrong-key/performance, SPHINCS+ key sizes/sign/verify/tamper, side-by-side comparison |
| `HybridOrchestratorIntegrationTest` (7 tests) | All three modes end-to-end through `PqcEncryptionService` (Phase 2), session isolation, upgrade path, hybrid key genuinely combines both secrets |

None of these require a Spring context — they instantiate the engine classes directly, consistent
with Phase 1 having zero Spring dependency.

```bash
mvn test -Dtest=KyberKemEngineTest,PqcSigningEnginesTest,HybridOrchestratorIntegrationTest
```

---

## What Phase 1 Does Not Solve

- **No persistent keys.** `HybridHandshakeOrchestrator`'s no-arg constructor generates a fresh
  ephemeral Kyber/EC key pair every time the JVM starts — a restart invalidates every session
  established against the old keys. [Phase 3](Phase3Implementation.md) (`QuantumKeyService`)
  solves this by injecting `Optional<QuantumKeyService>`, which the orchestrator uses when present.
- **No HTTP/Spring integration.** Phase 1 classes take Java objects in and return Java objects —
  there is no request/response cycle, no headers, no auto-configuration here.
  [Phase 2](Phase2Implementation.md) wires `HybridHandshakeOrchestrator` behind a servlet filter
  and exposes a `PqcEncryptionService` facade.
- **Signatures are not wired into authentication.** `DilithiumSigningEngine` signs arbitrary
  bytes — it knows nothing about JWTs, Spring Security, or token formats.
  [Phase 4](Phase4ImplementationDetails.md) builds the JWT layer on top of it.
