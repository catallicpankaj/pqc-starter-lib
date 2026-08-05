# PqcStarterLib — Full Phase Roadmap

> Complete breakdown of all 7 phases: what each does, current status, and why the order matters.

---

## Phase Overview

| Phase | Name | Status |
|---|---|---|
| Phase 1 | Core Cryptography Engine | ✅ Done |
| Phase 2 | Spring Boot Integration + Data Encryption | ✅ Done |
| Phase 3 | Key Management (KMS / Vault) | ✅ Done |
| Phase 4 | Spring Security + JWT | ✅ Done |
| Phase 5 | RSA Migration Bridge | ✅ Done |
| Phase 6 | Data at Rest (JPA + File Encryption) | ✅ Done |
| Phase 7 | TLS Layer (PQC-in-TLS 1.3) | 🔮 Future (ecosystem-dependent) |

---

## Phase 1 — Core Cryptography Engine ✅ Done

**Goal:** Implement real, non-simulated post-quantum cryptographic primitives using BouncyCastle.

### What Was Built

| Algorithm | NIST Standard | Purpose |
|---|---|---|
| Kyber-768 (ML-KEM) | FIPS 203 | Key encapsulation — replaces RSA key exchange |
| Dilithium-3 (ML-DSA) | FIPS 204 | Digital signatures — replaces RSA-sig / ECDSA |
| SPHINCS+-SHA2-128f (SLH-DSA) | FIPS 205 | Long-term signing, CAs |
| ECDHE-P384 | Classical | Paired with Kyber in hybrid mode |

### Hybrid Handshake — The Core Contribution

Three negotiated modes, switched at runtime per client capability:

```
CLASSICAL:  SessionKey = KDF(ECDHE_secret, session_id)
PQC_ONLY:   SessionKey = KDF(Kyber_secret, session_id)
HYBRID:     SessionKey = KDF(ECDHE_secret || Kyber_secret, session_id)
```

The HYBRID derivation formula:
```
SessionKey = HMAC-SHA256(ECDHE_secret || Kyber_secret, session_id)
```
An attacker must break **both** ECDHE-P384 **and** Kyber-768 to recover the session key.

### Key Files

- `KyberKemEngine.java` — Kyber-768 encapsulate / decapsulate
- `HybridHandshakeOrchestrator.java` — core runtime switching engine
- `DilithiumSigningEngine.java` — Dilithium-3 sign / verify
- `SphincsSigningEngine.java` — SPHINCS+ sign / verify
- `CipherMode.java` — CLASSICAL / PQC_ONLY / HYBRID enum
- `ClientCapability.java` — client PQC capability model
- `HandshakeSession.java` — session result + safe summary (no key material exposed)

### Verified Performance

| Mode | Avg Handshake | Quantum-Safe |
|---|---|---|
| CLASSICAL | sub-millisecond to ~1 ms | No |
| PQC_ONLY | sub-millisecond to ~1 ms | Yes |
| HYBRID | ~1–2 ms | Yes |
| Dilithium-3 sign+verify | ~1–2 ms | Yes |

Measured directly from this repo's test suite (`HybridOrchestratorIntegrationTest`,
`PqcSigningEnginesTest`) on commodity hardware, JDK 17, BouncyCastle 1.78.1 — actual numbers vary
by hardware and JIT warm-up state. See [`Phase1Implementation.md`](Phase1Implementation.md) for
the full measured breakdown including key/signature sizes.

---

## Phase 2 — Spring Boot Integration + Data Encryption ✅ Done

**Goal:** Wire Phase 1 crypto into a usable Spring Boot library. Plug the derived session key into real AES-256-GCM data encryption.

### What Was Built

**AES-256-GCM Engine (`AesGcmEngine.java`)**

The missing link between key exchange (Phase 1) and actual data protection. The session key from the hybrid handshake becomes the AES-256 key used to encrypt and decrypt your data.

```
Wire format:
┌─────────────────────────────────────────────────┐
│  IV (12 bytes)  │  Ciphertext + GCM Tag (N+16)  │
└─────────────────────────────────────────────────┘
```

- Every encryption uses a fresh random IV — no IV reuse
- GCM tag authenticates the ciphertext — any tampering throws `AEADBadTagException`
- Session ID passed as AAD — ciphertext is bound to its session, preventing replay attacks
- AES-256 is quantum-resistant (Grover's algorithm only reduces effective length to 128 bits — still unbreakable)

**PqcEncryptionService (`PqcEncryptionService.java`)**

Top-level service combining handshake + encrypt/decrypt into one simple API:

```java
HandshakeSession session = pqcEncryption.establishHybridSession("my-client");
String encrypted = pqcEncryption.encryptForSession(session.getSessionId(), payload);
String decrypted = pqcEncryption.decryptForSession(session.getSessionId(), encrypted);
```

**Other Components**

- `HybridHandshakeFilter.java` — Servlet filter: reads `X-PQC-*` headers, performs per-request mode switching, attaches session to request attributes
- `PqcActuatorEndpoint.java` — `/actuator/pqc` monitoring: active sessions, algorithm status, benchmark runner
- `PqcAutoConfiguration.java` — Spring Boot auto-configuration
- `EncryptionDemoController.java` — Demo REST endpoints for the full encrypt/decrypt pipeline

### What Phase 2 Enables

```
Client                              Server
──────                              ──────
1. Handshake (Kyber + ECDHE)   →   Derive shared session key
2. sessionKey = KDF(secrets)   =   sessionKey (same on both sides)
3. AES-256-GCM encrypt(data)   →   AES-256-GCM decrypt(data)
```

### Current Limitation (Resolved by Phase 3)

Session keys live in JVM heap memory only. A server restart makes all previously established session keys unrecoverable. This makes Phase 2 suitable for in-flight session encryption but not for persistent data-at-rest encryption until Phase 3 is complete.

---

## Phase 3 — Key Management (KMS / Vault) ✅ Done

**Goal:** Eliminate the in-memory key problem. Integrate with an external KMS so keys survive restarts, rotate on schedule, and are never held directly by the application.

### The Problem Being Solved

Before this phase:
- The Kyber private key was generated at startup and lived in JVM heap memory only
- A server restart meant all session keys were gone — any data encrypted against those keys became permanently unreadable
- Every microservice instance held a full copy of the master private key — a heap dump from any one instance would compromise everything
- No key rotation meant non-compliance with HIPAA, PCI-DSS, SOC 2 by definition
- Database backups taken at any point in time could not be reliably decrypted without key version tracking

### What Was Built

**KMS Integration — five pluggable providers behind one `KeyManagementProvider` strategy interface**

| Provider | Status |
|---|---|
| `LocalDevKeyProvider` | Full implementation — file-based AES-256-GCM, dev/test only |
| `HashiCorpVaultKeyProvider` | Full implementation — Vault Transit + KV v2 |
| `AwsKmsKeyProvider` | Stub with implementation guide |
| `AzureKeyVaultKeyProvider` | Stub with implementation guide |
| `GcpKmsKeyProvider` | Stub with implementation guide |

```
Master Key      → generated inside KMS/HSM, never leaves the KMS
Kyber keypair   → generated by BouncyCastle, private key wrapped by master key before storage
Dilithium keypair → same
ECDHE keypair   → same
Session key     → derived per-handshake, never stored
Data encryption → AES-256-GCM using session key
```

The application never holds the master key directly. All wrap/unwrap operations happen inside the KMS.

**Bootstrap Flow (`QuantumKeyService.bootstrap()`, first startup)**

```
1. BouncyCastle generates Kyber-768 / EC-P384 / Dilithium-3 keypairs
2. App sends each private key to the provider → provider wraps it with the master key
3. App stores wrapped private key via provider.storeKeyVersion()
4. App registers the public key + version in KeyRegistry
5. Done — keypairs persist across restarts
```

**Every Restart After That**

```
1. App asks the provider for the wrapped private key (provider.loadKeyVersion())
2. Provider unwraps it using the master key
3. App reconstructs the same persistent KeyPair from the raw bytes
4. No new keypair generated — identity is stable
```

**Key Rotation (`QuantumKeyService.rotate()`, e.g. every 90 days via `KeyRotationManager`)**

```
1. BouncyCastle generates a NEW keypair
2. New private key wrapped with master key → stored as ACTIVE, version N+1
3. New public key registered in KeyRegistry as version N+1
4. Previous version kept, marked DEPRECATED — still usable for decrypting old sessions
5. After the deprecation window (KeyRotationManager, scheduled) — old version RETIRED
```

**`HybridHandshakeOrchestrator` and `DilithiumKeyPairHolder` both accept `Optional<QuantumKeyService>`** — when a KMS provider is configured, they resolve the active key pair fresh from `QuantumKeyService` on every use (rather than caching it once at construction), so a scheduled or manual rotation takes effect on the very next handshake/token issuance with no restart required. When Phase 3 is absent, they fall back to a single ephemeral in-memory key pair generated once at startup.

**15 unit tests** in `KeyManagementProviderTest` — bootstrap, restart persistence, rotation
(including that a rotation is reflected live by the orchestrator, the JWT key holder, and the
`/actuator/pqc` `keyManagement` block), wrap/unwrap tamper rejection, orchestrator integration,
no Spring context required.

**Detailed documentation:** [`Phase3Implementation.md`](Phase3Implementation.md) — architecture
diagrams, sequence diagrams, per-provider setup, adding a new provider.

### Why This Was the Most Critical Phase

Without persistent key management, everything else is a prototype. It is the foundation that
makes data-at-rest encryption (Phase 6) production-safe — Phase 6 depends on Phase 3 being in
place first.

---

## Phase 4 — Spring Security + JWT ✅ Done

**Goal:** Replace RSA/ECDSA in the authentication layer with quantum-safe Dilithium-3 signing.

### What Was Built

- **Dilithium-3 signed JWT tokens** (`DilithiumJwtService`) — structurally a standard JWT
  (`Base64Url(header).Base64Url(payload).Base64Url(signature)`) with `alg: DILITHIUM3`, replacing
  RS256/ES256 as the signing algorithm
- **`DilithiumJwtFilter`** — Bearer token filter, wired into the Spring Security chain via
  `SecurityConfig`'s `addFilterBefore(dilithiumJwtFilter, UsernamePasswordAuthenticationFilter.class)`
- **`DilithiumJwtAuthController`** — `POST /auth/token` (issue), `GET /api/secure` (protected
  resource requiring a valid token)
- **`DilithiumKeyPairHolder`** — accepts `Optional<QuantumKeyService>`, so JWT signing keys are
  KMS-managed when Phase 3 is configured, ephemeral otherwise
- **`pqc.jwt.*`** configuration — `ttl-minutes` (default 60), `demo-password` (default
  `secret` — must be overridden in production)

**11 unit tests** in `DilithiumJwtTest` — token issuance, validation, expiry, tampered-signature
rejection, wrong-key rejection, no Spring context required.

**Detailed documentation:** [`Phase4ImplementationDetails.md`](Phase4ImplementationDetails.md) —
token format, sequence diagrams for issuance and validation, Phase 3 integration, test coverage.

**Not built:** OAuth2/OIDC integration and mTLS with Dilithium X.509 certificates were part of the
original Phase 4 scope but were not implemented — JWT issuance/validation over the standard
`Authorization: Bearer` flow is what shipped. See
[`AlgoChoicesForJWT.md`](AlgoChoicesForJWT.md) for why Dilithium-3 (not Kyber or SPHINCS+) was
chosen for signing.

### Why This Matters

Long-lived service account tokens and JWT tokens signed with RSA are vulnerable to a "harvest now,
decrypt later" attack — a quantum adversary captures them now and breaks the RSA signature once a
quantum computer is available. Dilithium-3 signatures eliminate this future exposure.

### Note on Priority

Phase 4 protects the *authentication layer*, not the data itself. Phase 3 (key management) and
Phase 6 (at-rest encryption) have more direct impact on protecting actual data bytes — but all
three are now complete.

---

## Phase 5 — RSA Migration Bridge ✅ Done

**Goal:** Allow gradual, service-by-service migration from RSA/ECDSA to Kyber/Dilithium without a hard cut-over.

### The Problem Being Solved

In any real organisation, you cannot flip all services to PQC overnight. During the migration window you will have:
- Legacy services signing and encrypting with RSA-2048 or ECDSA
- New services already using PqcStarterLib's Kyber/Dilithium

Without a migration bridge, these two groups cannot communicate securely. A hard cut-over is not feasible in production.

### What Was Built

**Three migration modes (`MigrationMode` enum):**

| Mode | Behaviour | Quantum-Safe |
|------|-----------|-------------|
| `RSA_ONLY` | RSA-2048 OAEP key transport — legacy simulation | No |
| `BRIDGE` | PQC preferred; RSA fallback based on `rolloutPercentage` | Partial |
| `PQC_ONLY` | Kyber/Hybrid only — fully migrated, refuses RSA path | Yes |

**`RsaKeyConverter`** — RSA-2048 OAEP key wrap/unwrap. Implements the RSA key transport
pattern (client encrypts 32-byte session key with server's RSA public key; server decrypts
with private key). Uses OAEP-SHA256, not PKCS#1 v1.5.

**`RsaKyberBridgeService`** — core bridge routing:
- `establishSession(clientId, requestedMode)` — resolves effective mode (per-service override → requested mode), then routes to RSA or PQC path
- RSA path: generates session key, wraps with RSA, unwraps → `HandshakeSession(CLASSICAL)`
- PQC path: delegates to `HybridHandshakeOrchestrator` → `HandshakeSession(HYBRID)`
- AtomicLong counters track every session for rollout metrics

**`RsaMigrationProperties`** (`pqc.migration.*`):
- `defaultMode` — BRIDGE by default
- `rolloutPercentage` — 0–100 % of BRIDGE sessions routed to PQC (default 100)
- `serviceOverrides` — per-clientId forced mode, overrides global settings

**`RsaMigrationController`** (`/api/migration/*`):
- `POST /bridge-handshake` — session using configured default mode
- `POST /simulate-legacy` — forces RSA_ONLY path
- `POST /simulate-pqc` — forces PQC_ONLY path
- `GET  /status` — live migration stats + rollout %
- `GET  /rsa-public-key` — server RSA public key metadata

**`RsaMigrationAutoConfiguration`** — Spring Boot auto-wiring activated by
`pqc.migration.enabled=true` (default).

**10 unit tests** in `RsaMigrationBridgeTest` — no Spring context required.

**Detailed documentation:** `Phase5ImplementationDetails.md` — architecture diagrams,
sequence diagrams, five rollout scenarios, curl examples, design decision rationale.

### Why the Order Matters

Phase 5 makes Phase 4's Dilithium JWT deployable in practice — you need a way to
serve both RSA and PQC-signed tokens during the transition window, migrating one
service at a time rather than waiting for a fleet-wide freeze.

---

## Phase 6 — Data at Rest (JPA + File Encryption) ✅ Done

**Goal:** Full application-layer tooling for encrypting data before it is written to a database or file system.

### What Was Built

**`HkdfKeyDerivation` — Per-Record Key Isolation via HKDF-SHA256**

Each field on each record gets a unique AES-256 key derived from the master key:

```
recordKey = HKDF-SHA256(masterKey, salt=recordId, info="fieldName:keyVersion")
```

A breach of one field's derived key exposes nothing about any other field or record.

**`@EncryptedField` annotation**

Marks JPA entity fields for transparent encryption. Purely documentary at the annotation level — enforced by the converter below.

**`EncryptedAttributeConverter` — Transparent JPA Integration**

Abstract `jakarta.persistence.AttributeConverter<String, String>` base class. Subclasses provide `getService()`, `getFieldName()`, and optionally `getRecordId()` for per-row isolation.

```java
@EncryptedField
@Convert(converter = SsnConverter.class)
@Column(length = 512)
private String ssn;   // stored as "v1:<base64>" — decrypted automatically on SELECT
```

**Versioned Field Format**

All encrypted field values carry an explicit key version prefix:
```
v{keyVersion}:{Base64(IV || Ciphertext+GCM-Tag)}
```
Examples: `v1:AAEC...` (current), `v2:BBFD...` (after rotation)

**`StreamingAesGcmEngine` — Chunked File Encryption**

Custom PQCS wire format for files of arbitrary size with bounded memory usage:

```
[Magic "PQCS" 4B][Version 1B][ChunkSize 4B]
[ChunkLen 4B][IV 12B][Ciphertext+GCM-Tag]
[ChunkLen 4B][IV 12B][Ciphertext+GCM-Tag]
[ChunkLen=0]  ← EOF marker
```

Each 4 KB chunk is independently AES-256-GCM encrypted with its own random IV. Chunk index is AAD — prevents reordering attacks. Default chunk: 4096 bytes (configurable).

**`ReEncryptionService` — Key Rotation Migration**

Supports two re-encryption strategies:

| Strategy | When | How |
|----------|------|-----|
| LAZY | On each read | Read v1 ciphertext → decrypt → re-encrypt → write v2 back before returning |
| EAGER | Batch job | Iterate all records, calling `reEncryptField` for each |

Takes both `previousService` (old key, for decryption) and `currentService` (new key, for re-encryption) — enables safe cross-version migration.

**`AtRestEncryptionService` — Top-Level API**

Single injectable service combining all capabilities:

```java
// Field encryption (JPA)
String stored    = atRest.encryptField("123-45-6789", "patient-42", "ssn");
String plaintext = atRest.decryptField(stored, "patient-42", "ssn");

// File encryption
atRest.encryptFile(fileKey, inputStream, outputStream);
atRest.decryptFile(fileKey, inputStream, outputStream);

// Key rotation
String rekeyed = atRest.reEncryptIfNeeded(stored, "patient-42", "ssn");
```

**`AtRestEncryptionController` — REST API (`/api/atrest/*`)**

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/encrypt-field` | Encrypt a sensitive field value |
| POST | `/decrypt-field` | Decrypt a stored field value |
| POST | `/reencrypt-field` | Re-encrypt under current key version |
| POST | `/encrypt-bytes` | Encrypt raw bytes (Base64 in/out) |
| POST | `/decrypt-bytes` | Decrypt raw bytes (Base64 in/out) |
| GET  | `/status` | Current key version, chunk size |

**`AtRestEncryptionAutoConfiguration`** — Spring Boot auto-wiring, activated by `pqc.atrest.enabled=true` (default). If `masterKeyHex` is blank, generates an ephemeral random key (dev mode) and logs a warning. Supports `previous-master-key-hex` for genuine master key rotation — see [Configuration Reference](../README.md#configuration-reference).

**14 unit tests** in `DataAtRestEncryptionTest` — no Spring context required:
- HKDF field isolation (different fields → different keys)
- HKDF row isolation (different recordIds → different keys)
- Field encrypt/decrypt round-trip
- Field encryption randomness (same plaintext → different ciphertext)
- `needsReEncryption` version detection
- Streaming round-trip for small payloads
- Streaming round-trip for multi-chunk payloads (32-byte chunks)
- Streaming wrong-key authentication failure
- `reEncryptIfNeeded` v1→v2 migration with plaintext preservation
- `reEncryptIfNeeded` idempotence (no-op on current version)
- `AtRestEncryptionService.encryptBytes/decryptBytes` round-trip
- `AtRestEncryptionAutoConfiguration` rotation wiring: `previous-master-key-hex` preserves data across a genuine key change
- `AtRestEncryptionAutoConfiguration` single-key fallback when no rotation is in progress

### Relationship to Phase 3

Phase 3 is the plumbing (KMS, key persistence, rotation policy). Phase 6 is the application integration that sits on top:

| What It Does | Who Does It |
|---|---|
| Master key lives in KMS, never in app memory | Phase 3 |
| Private keys persist across restarts | Phase 3 |
| Key rotation schedule + versioning | Phase 3 |
| JPA field auto-encrypt/decrypt | Phase 6 |
| Per-record key derivation | Phase 6 |
| File streaming encryption | Phase 6 |
| Re-encrypting stored data on rotation | Phase 6 |

**Detailed documentation:** `Phase6ImplementationDetails.md` — architecture diagrams, sequence diagrams, field format specification, key rotation scenarios, curl examples.

---

## Phase 7 — TLS Layer 🔮 Future (ecosystem-dependent)

**Goal:** PQC cipher suites inside TLS 1.3, so external traffic (browsers, mobile apps, third-party APIs) is quantum-safe at the transport layer.

### Why This Is Last

This phase is not blocked by engineering effort — it is blocked by external ecosystem readiness:

1. **NIST standardisation** — PQC cipher suites for TLS 1.3 are still being finalised
2. **Certificate Authority support** — DigiCert, Let's Encrypt, and others need to issue Dilithium X.509 certificates
3. **Browser vendors** — Chrome, Firefox, Safari need to implement and ship PQC TLS handshakes
4. **TLS library updates** — OpenSSL, BoringSSL, Java's JSSE all need PQC support in stable releases

Timeline: **2–3 years** for mainstream production adoption.

### What Can Be Done Now (No Waiting Required)

The dual-layer approach already enabled by Phase 2:

```
Layer 1 (TLS):     Classical RSA/ECDH — stops today's attackers
Layer 2 (Payload): Kyber+AES via PqcStarterLib — stops quantum attackers
```

Both layers must be broken independently. A quantum adversary breaks TLS but still hits the Kyber-encrypted payload. A classical adversary cannot break TLS in the first place. This is the approach NIST recommends during the migration period — do not rip out TLS, add PQC payload encryption on top of it.

### What Phase 7 Will Add (When Ecosystem Is Ready)

- PQC cipher suite configuration for embedded Tomcat / Netty
- Dilithium-signed X.509 certificates generated from the keys already managed by Phase 3
- mTLS with Dilithium certificates (building on Phase 4's certificate work)
- Drop-in replacement for classical TLS configuration in `application.yml`

---

## The Honest Gap Map (Current State)

```
                WHAT EXISTS NOW
                ───────────────

   [Kyber KEM]──→[Hybrid KDF]──→[AES-256-GCM]
        ↑               ↑              ↑
     Phase 1         Phase 1        Phase 2

   This is a cryptographic ENGINE — not a system.
   It proves the algorithms work correctly.
   It is NOT yet plugged into production infrastructure.

                WHAT IS MISSING
                ───────────────

  For Transit:                   For Rest:
  ┌───────────────────────┐      ┌─────────────────────────┐
  │ TLS layer          ·  │      │ KMS / HSM integration ✅│
  │ X.509 certs           │      │ KeyStore persistence  ✅│
  │ Spring Security    ✅ │      │ Per-record key derive ✅│
  │ JWT / OAuth2       ✅ │      │ DB field encryption   ✅│
  │ RSA migration      ✅ │      │ File streaming        ✅│
  │ Key rotation       ✅ │      │ Key rotation          ✅│
  └───────────────────────┘      └─────────────────────────┘
     Phase 7 remaining                 All done ✅
```

---

## Production Readiness by Use Case

| Use Case | Ready? | Blocking Phases |
|---|---|---|
| Microservice payload encryption (internal) | ⚠️ Partial | Phase 3 (key management) |
| Replacing RSA in existing APIs | ✅ Yes | — (Phase 4 + 5 done) |
| JWT / OAuth2 token signing | ✅ Yes | — (Phase 4 done) |
| Database field encryption | ✅ Yes | — (Phase 6 done) |
| File encryption | ✅ Yes | — (Phase 6 done) |
| TLS / HTTPS replacement | No | Phase 7 (years away) |

---

## Build Order (as delivered)

```
Phase 1  →  Phase 2  →  Phase 3  →  Phase 4  →  Phase 5  →  Phase 6  →  Phase 7
 Core        Spring       KMS       Security    Migration    At-Rest       TLS
 crypto      integration  (done)   (auth layer) (rollout)   (storage)  (ecosystem)
 (done)      (done)                  (done)       (done)      (done)   (future)
```

Phase 3 (key management) shipped before Phase 4 (JWT) deliberately — JWT signing keys and the
handshake's identity keys both need somewhere persistent to live, so key management had to exist
first for Phase 4's `DilithiumKeyPairHolder` to have a KMS to optionally bind to.

**Phases 1–6 complete.** Core crypto, session encryption, key management, JWT auth,
RSA migration bridge, and full data-at-rest encryption are all production-ready
(pending production KMS wiring — i.e. actually pointing `pqc.key-management.provider` at
Vault/AWS/Azure/GCP instead of `local`, since `local` is dev-only by design).

**Remaining:** Phase 7 (PQC TLS) — blocked on external ecosystem readiness (CA support, browser
support, TLS 1.3 PQC cipher suite standardization), not on engineering effort within this project.
Estimated 2–3 years for mainstream adoption; see the Phase 7 section above for what can be done in
the meantime.
