# Phase 5 — RSA Migration Bridge: Implementation Details

> Enables gradual, service-by-service migration from RSA-2048 to Kyber-768 / Hybrid PQC
> without a hard cut-over. Legacy and modern services coexist during the migration window.

---

## Why It Was Needed

### The Hard Cut-Over Problem

After Phases 1–4, PqcStarterLib can fully replace RSA/ECDSA with Kyber-768 and
Dilithium-3. But in any real organisation, a hard flip-the-switch migration is
not feasible:

```
Reality of a production fleet on Day 1 of migration:
┌─────────────────────────────────────────────────────────────┐
│  Legacy Service A  │  RSA-2048 only — cannot speak PQC     │
│  Legacy Service B  │  RSA-2048 only — cannot speak PQC     │
│  Modern Service C  │  Kyber-768 + Dilithium-3 capable       │
│  Modern Service D  │  Being migrated — needs both sides     │
└─────────────────────────────────────────────────────────────┘
```

Without a migration bridge:
- Legacy A cannot call Modern C — they speak different key exchange protocols
- A full deployment freeze is needed to switch everything at once
- A single incompatible service blocks the whole fleet from migrating
- There is no way to measure rollout progress or do a canary release

### What "Harvest Now, Decrypt Later" Means for Migration Timing

A quantum adversary is already recording encrypted RSA traffic today. Every day
you delay migrating a service is another day of traffic captured under RSA — which
a sufficiently powerful quantum computer will decrypt retroactively.

The migration bridge is not about convenience. It is the mechanism that lets you
start moving the clock today, one service at a time, rather than waiting for a
mythical zero-downtime day when every service migrates simultaneously.

### The Specific Gap Phase 5 Fills

| Phase 4 gave us | Phase 5 adds |
|----------------|--------------|
| Quantum-safe JWT tokens (Dilithium-3) | A way to issue those tokens even when some services still expect RSA tokens |
| Kyber key exchange for fully-migrated peers | RSA key exchange for peers that can't do Kyber yet |
| Drop-in PQC for ready services | Gradual rollout tooling for services that aren't ready |

---

## What Was Built

### New Files

```
src/main/java/com/pqc/hybrid/migration/
├── MigrationMode.java                  ← RSA_ONLY / BRIDGE / PQC_ONLY enum
├── MigrationStats.java                 ← Snapshot record: RSA vs PQC session counts
├── RsaKeyConverter.java                ← RSA-2048 OAEP key wrap/unwrap utility
├── RsaKyberBridgeService.java          ← Core bridge: routes sessions to RSA or PQC
├── RsaMigrationController.java         ← REST endpoints: /api/migration/*
└── config/
    ├── RsaMigrationProperties.java     ← rolloutPercentage, serviceOverrides config
    └── RsaMigrationAutoConfiguration.java  ← Spring Boot auto-wiring

src/test/java/com/pqc/hybrid/migration/
└── RsaMigrationBridgeTest.java         ← 10 unit tests
```

### Modified Files

| File | Change |
|------|--------|
| `SecurityConfig.java` | Added `/api/migration/**` to permitAll routes |
| `application.yml` | Added Phase 5 migration config block (commented) |
| `AutoConfiguration.imports` | Registered `RsaMigrationAutoConfiguration` |
| `README.md` | Phase 5 section, updated curl examples and test count |

---

## Architecture

### Component Diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│                         Phase 5 — Migration Bridge                      │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                   RsaKyberBridgeService                          │   │
│  │                                                                   │   │
│  │   establishSession(clientId, requestedMode)                       │   │
│  │        │                                                          │   │
│  │        ▼                                                          │   │
│  │   resolveMode(clientId, requestedMode)                           │   │
│  │        │ ← serviceOverrides map takes precedence                 │   │
│  │        │ ← falls back to requestedMode if no override            │   │
│  │        │                                                          │   │
│  │        ├─── RSA_ONLY ──→ performRsaSession()                    │   │
│  │        │                      │                                   │   │
│  │        │                      ▼                                   │   │
│  │        │               RsaKeyConverter                            │   │
│  │        │               · generate 32 random bytes                 │   │
│  │        │               · wrapKeyMaterial() — RSA-OAEP encrypt    │   │
│  │        │               · unwrapKeyMaterial() — RSA-OAEP decrypt  │   │
│  │        │               · HandshakeSession(CLASSICAL, RSA-2048)   │   │
│  │        │                                                          │   │
│  │        ├─── PQC_ONLY ──→ performPqcSession()                    │   │
│  │        │                      │                                   │   │
│  │        │                      ▼                                   │   │
│  │        │               HybridHandshakeOrchestrator               │   │
│  │        │               · ClientCapability(HYBRID, Kyber-768)     │   │
│  │        │               · orchestrate() → HYBRID session          │   │
│  │        │               · HandshakeSession(HYBRID, Kyber+ECDHE)  │   │
│  │        │                                                          │   │
│  │        └─── BRIDGE ───→ performBridgeSession()                  │   │
│  │                               │                                   │   │
│  │                               ├── rolloutPercentage check         │   │
│  │                               ├── random < rollout% → PQC path   │   │
│  │                               └── else → RSA fallback path       │   │
│  │                                                                   │   │
│  │   AtomicLong counters: rsaCount, bridgeToPqcCount,               │   │
│  │                        bridgeToRsaCount, pqcOnlyCount            │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  RsaMigrationProperties                                                  │
│    defaultMode: BRIDGE                                                   │
│    rolloutPercentage: 100                                                │
│    serviceOverrides: { "billing": RSA_ONLY, "auth": PQC_ONLY }          │
│                                                                          │
│  RsaMigrationController        RsaMigrationAutoConfiguration            │
│    POST /bridge-handshake       @Bean RsaKeyConverter                   │
│    POST /simulate-legacy        @Bean RsaKyberBridgeService             │
│    POST /simulate-pqc           @Bean RsaMigrationController            │
│    GET  /status                 @EnableConfigurationProperties          │
│    GET  /rsa-public-key                                                  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Key Mechanics

### MigrationMode — Three Modes

```
RSA_ONLY
  └─ Always uses RSA-2048 OAEP key transport.
     CipherMode: CLASSICAL | quantumSafe: false
     Use case: testing legacy path, legacy services not yet migrated

BRIDGE
  └─ Dual-mode: checks rolloutPercentage to route to PQC or RSA.
     Per-service overrides in serviceOverrides take precedence.
     Use case: gradual rollout — increase % over time as confidence grows

PQC_ONLY
  └─ Always uses Kyber-768 + ECDHE-P384 HYBRID.
     CipherMode: HYBRID | quantumSafe: true
     Use case: services fully migrated — lock them in, refuse RSA path
```

### RSA-2048 OAEP Key Transport (the RSA Path)

The RSA path implements **RSA key transport** — the key exchange pattern used
in TLS 1.2 RSA cipher suites (since superseded in TLS 1.3):

```
Client side:
  1. Generate 32 random bytes (session key material)
  2. Encrypt with server's RSA-2048 public key using OAEP-SHA256
     wrapped = RSA_OAEP_Encrypt(serverPubKey, sessionKeyMaterial)

Server side:
  3. Decrypt with RSA private key
     recovered = RSA_OAEP_Decrypt(serverPrivKey, wrapped)

Both sides now share the same 32-byte session key.
```

Why OAEP (not PKCS#1 v1.5):
- OAEP is semantically secure — probabilistic padding, different ciphertext each call
- PKCS#1 v1.5 is vulnerable to Bleichenbacher's chosen-ciphertext attack
- OAEP-SHA256 is the modern standard (RFC 8017)

The wrapped ciphertext is 256 bytes for RSA-2048 (~8× the 32-byte plaintext).
In a real deployment, the client would receive the server's RSA public key via
`GET /api/migration/rsa-public-key` and perform the encryption itself.

### BRIDGE Mode — Rollout Percentage Logic

```java
private HandshakeSession performBridgeSession(String clientId) throws Exception {
    boolean usePqc = (rng.nextInt(100) < props.getRolloutPercentage());
    if (usePqc) {
        // PQC path — Kyber/ECDHE HYBRID
    } else {
        // RSA fallback
    }
}
```

This gives a statistically correct distribution:
- `rolloutPercentage = 0`   → `nextInt(100) < 0` is always false → always RSA
- `rolloutPercentage = 50`  → approximately 50/50 split
- `rolloutPercentage = 100` → `nextInt(100) < 100` is always true → always PQC

### Per-Service Override Resolution

```java
private MigrationMode resolveMode(String clientId, MigrationMode requestedMode) {
    return props.getServiceOverrides().getOrDefault(clientId, requestedMode);
}
```

Resolution order (highest priority first):
1. `serviceOverrides[clientId]` — pinned mode for this specific service
2. `requestedMode` — what the caller asked for (typically `defaultMode`)

This means a service pinned to `RSA_ONLY` stays RSA even if the global default
is `PQC_ONLY`. Useful when a specific service has a hard dependency on RSA that
cannot be removed until a specific sprint.

### Unified Session Format

Both RSA and PQC paths return the same `HandshakeSession` type with the same
32-byte session key material. Downstream code (`PqcEncryptionService`, data
encryption, etc.) works identically regardless of which path was taken.

```
RSA path:   HandshakeSession { cipherMode=CLASSICAL, sessionKey[32], classicalAlgo="RSA-2048-OAEP" }
PQC path:   HandshakeSession { cipherMode=HYBRID,    sessionKey[32], pqcKemAlgo="Kyber-768" }
```

The only difference observable downstream is `isQuantumSafe()` — true for PQC,
false for RSA. Telemetry and monitoring should key on this flag.

---

## Sequence Diagrams

### RSA_ONLY Session (Legacy Path)

```
  Caller             RsaKyberBridgeService        RsaKeyConverter
    │                         │                         │
    │  establishSession(      │                         │
    │    clientId,            │                         │
    │    RSA_ONLY)            │                         │
    │────────────────────────>│                         │
    │                         │  resolveMode()           │
    │                         │  → RSA_ONLY (no override)│
    │                         │                         │
    │                         │  generate 32 random bytes (sessionKeyMaterial)
    │                         │                         │
    │                         │  wrapKeyMaterial(bytes) │
    │                         │────────────────────────>│
    │                         │                         │  Cipher(RSA/ECB/OAEPWithSHA256)
    │                         │                         │  encrypt with serverPublicKey
    │                         │<────────────────────────│
    │                         │  wrapped[256]           │
    │                         │                         │
    │                         │  unwrapKeyMaterial(wrapped)
    │                         │────────────────────────>│
    │                         │                         │  decrypt with serverPrivateKey
    │                         │<────────────────────────│
    │                         │  recovered[32]          │
    │                         │                         │
    │                         │  rsaCount.incrementAndGet()
    │                         │                         │
    │<────────────────────────│                         │
    │  HandshakeSession {     │                         │
    │    cipherMode: CLASSICAL│                         │
    │    sessionKey[32]       │                         │
    │    algo: RSA-2048-OAEP  │                         │
    │    quantumSafe: false   │                         │
    │  }                      │                         │
```

### PQC_ONLY Session (Fully-Migrated Path)

```
  Caller         RsaKyberBridgeService      HybridHandshakeOrchestrator
    │                    │                            │
    │  establishSession( │                            │
    │    clientId,       │                            │
    │    PQC_ONLY)       │                            │
    │───────────────────>│                            │
    │                    │  resolveMode()              │
    │                    │  → PQC_ONLY (no override)  │
    │                    │                            │
    │                    │  pqcOnlyCount.incrementAndGet()
    │                    │                            │
    │                    │  ClientCapability {         │
    │                    │    pqcCapable: true         │
    │                    │    hybridCapable: true      │
    │                    │    algos: Kyber-768         │
    │                    │  }                          │
    │                    │                            │
    │                    │  orchestrate(capability)   │
    │                    │───────────────────────────>│
    │                    │                            │  negotiateBestMode() → HYBRID
    │                    │                            │
    │                    │                            │  ECDHE-P384 key agreement
    │                    │                            │  Kyber-768 encapsulate/decapsulate
    │                    │                            │  HMAC-SHA256(ECDHE || Kyber, sessionId)
    │                    │<───────────────────────────│
    │                    │  HandshakeSession {         │
    │                    │    cipherMode: HYBRID       │
    │                    │    sessionKey[32]           │
    │                    │    algo: Kyber-768          │
    │                    │    quantumSafe: true        │
    │                    │  }                          │
    │<───────────────────│                            │
    │  (same session)    │                            │
```

### BRIDGE Session — PQC Branch (rollout% = 75, dice roll < 75)

```
  Caller         RsaKyberBridgeService      HybridHandshakeOrchestrator
    │                    │                            │
    │  establishSession( │                            │
    │    clientId,       │                            │
    │    BRIDGE)         │                            │
    │───────────────────>│                            │
    │                    │  resolveMode()              │
    │                    │  → BRIDGE (no override)    │
    │                    │                            │
    │                    │  rng.nextInt(100) = 42 < 75
    │                    │  → PQC branch              │
    │                    │                            │
    │                    │  bridgeToPqcCount.incrementAndGet()
    │                    │                            │
    │                    │  orchestrate(HYBRID cap)   │
    │                    │───────────────────────────>│
    │                    │                            │  HYBRID handshake
    │<───────────────────│  HandshakeSession(HYBRID)  │
```

### BRIDGE Session — RSA Fallback Branch (rollout% = 75, dice roll ≥ 75)

```
  Caller         RsaKyberBridgeService        RsaKeyConverter
    │                    │                         │
    │  establishSession( │                         │
    │    clientId,       │                         │
    │    BRIDGE)         │                         │
    │───────────────────>│                         │
    │                    │  rng.nextInt(100) = 88 ≥ 75
    │                    │  → RSA fallback          │
    │                    │                         │
    │                    │  bridgeToRsaCount.incrementAndGet()
    │                    │                         │
    │                    │  performRsaSession(      │
    │                    │    clientId,             │
    │                    │    isBridgeFallback=true)│
    │                    │                         │
    │                    │  (RSA key exchange — see RSA_ONLY sequence above)
    │<───────────────────│  HandshakeSession(CLASSICAL, RSA-2048-OAEP)
```

### Per-Service Override (override wins over requestedMode)

```
  Caller                   RsaKyberBridgeService
    │                              │
    │  establishSession(           │
    │    "billing-legacy",         │
    │    PQC_ONLY)  ← caller wants PQC
    │─────────────────────────────>│
    │                              │  resolveMode("billing-legacy", PQC_ONLY)
    │                              │    serviceOverrides["billing-legacy"] = RSA_ONLY
    │                              │    → effective = RSA_ONLY  ← override wins
    │                              │
    │                              │  performRsaSession("billing-legacy", false)
    │<─────────────────────────────│
    │  HandshakeSession(CLASSICAL) │
    │  quantumSafe: false          │
```

---

## REST API Reference

### POST /api/migration/bridge-handshake

Establishes a session using the configured `defaultMode`.
In BRIDGE mode, routes to PQC or RSA based on `rolloutPercentage`.
Per-service overrides take precedence.

**Request:**
```
POST /api/migration/bridge-handshake?clientId=my-service
```

**Response:**
```json
{
  "sessionId": "A3F8C1D290E4B572",
  "requestedMode": "BRIDGE",
  "negotiatedCipherMode": "HYBRID",
  "quantumSafe": true,
  "classicalAlgorithm": "ECDHE-P384",
  "pqcKemAlgorithm": "Kyber-768",
  "handshakeDurationMs": 4.2
}
```

---

### POST /api/migration/simulate-legacy

Forces RSA_ONLY path regardless of config. Simulates a legacy RSA-only peer.
Use this during testing to validate that your RSA path still works before
removing RSA support from a service.

**Request:**
```
POST /api/migration/simulate-legacy?clientId=billing-service
```

**Response:**
```json
{
  "sessionId": "B1E2F3A490D5C672",
  "requestedMode": "RSA_ONLY",
  "negotiatedCipherMode": "CLASSICAL",
  "quantumSafe": false,
  "classicalAlgorithm": "RSA-2048-OAEP",
  "pqcKemAlgorithm": "none",
  "handshakeDurationMs": 1.1
}
```

---

### POST /api/migration/simulate-pqc

Forces PQC_ONLY path regardless of config. Simulates a fully-migrated peer.
Use this to test the PQC path in isolation before changing the default mode.

**Request:**
```
POST /api/migration/simulate-pqc?clientId=auth-service
```

**Response:**
```json
{
  "sessionId": "C9D0E1F290A3B472",
  "requestedMode": "PQC_ONLY",
  "negotiatedCipherMode": "HYBRID",
  "quantumSafe": true,
  "classicalAlgorithm": "ECDHE-P384",
  "pqcKemAlgorithm": "Kyber-768",
  "handshakeDurationMs": 5.3
}
```

---

### GET /api/migration/status

Live migration statistics. Use this to measure rollout progress.

**Request:**
```
GET /api/migration/status
```

**Response:**
```json
{
  "phase": "Phase 5 — RSA Migration Bridge",
  "defaultMode": "BRIDGE",
  "rolloutPercentage": "75%",
  "serviceOverrides": {
    "billing-legacy": "RSA_ONLY",
    "auth-svc": "PQC_ONLY"
  },
  "rsaSessions": 12,
  "bridgeToPqcSessions": 61,
  "bridgeToRsaSessions": 19,
  "pqcOnlySessions": 45,
  "quantumSafeSessions": 106,
  "totalSessions": 137,
  "pqcMigrationPercent": "77.4%"
}
```

---

### GET /api/migration/rsa-public-key

Returns metadata about the server's RSA public key. In a real deployment,
legacy clients would fetch this key to encrypt their 32-byte session key
material before sending it to the server.

**Request:**
```
GET /api/migration/rsa-public-key
```

**Response:**
```json
{
  "algorithm": "RSA-2048",
  "format": "X.509 SubjectPublicKeyInfo",
  "encodedLength": "294 bytes",
  "purpose": "RSA-OAEP key transport — encrypt 32-byte session key with this key"
}
```

---

## curl Examples

```bash
# Start the application
mvn spring-boot:run

# ── Bridge handshake (default BRIDGE mode, 100% rollout to PQC) ─────────
curl -X POST "http://localhost:8080/api/migration/bridge-handshake?clientId=my-svc"

# ── Simulate legacy RSA-only service ─────────────────────────────────────
curl -X POST "http://localhost:8080/api/migration/simulate-legacy?clientId=billing-svc"

# ── Simulate fully-migrated PQC service ──────────────────────────────────
curl -X POST "http://localhost:8080/api/migration/simulate-pqc?clientId=auth-svc"

# ── Live migration stats ──────────────────────────────────────────────────
curl http://localhost:8080/api/migration/status

# ── Server RSA public key info ────────────────────────────────────────────
curl http://localhost:8080/api/migration/rsa-public-key

# ── Run multiple bridge handshakes to see stats build up ─────────────────
for i in $(seq 1 10); do
  curl -s -X POST "http://localhost:8080/api/migration/bridge-handshake?clientId=svc-$i" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(f\"svc-$i → {d['negotiatedCipherMode']} (quantumSafe={d['quantumSafe']})\")"
done
curl http://localhost:8080/api/migration/status
```

---

## Configuration Reference

```yaml
pqc:
  migration:
    enabled: true                    # Master switch. Default: true.

    default-mode: BRIDGE             # RSA_ONLY | BRIDGE | PQC_ONLY
                                     # Applied when clientId has no override.
                                     # Default: BRIDGE.

    rollout-percentage: 75           # 0–100. Percentage of BRIDGE sessions
                                     # routed to PQC. The rest fall back to RSA.
                                     # 100 = fully PQC (default).
                                     # 0   = all RSA (rollout not started).

    service-overrides:               # Pin specific services to a forced mode.
      billing-legacy: RSA_ONLY       # Overrides default-mode + rollout-%
      auth-svc: PQC_ONLY             # for this clientId only.
      payment-svc: BRIDGE            # Explicit — same as default here.
```

---

## Example Scenarios

### Scenario 1 — Starting Migration (Day 0)

You have 20 services, all on RSA. Set up the bridge with 0% rollout to verify
the RSA path works correctly via the new bridge layer before touching anything:

```yaml
migration:
  default-mode: BRIDGE
  rollout-percentage: 0       # All sessions use RSA path — no PQC yet
```

Check `/api/migration/status`: `pqcMigrationPercent` should be `0.0%`.
Your services continue working exactly as before. No regression.

---

### Scenario 2 — Canary Rollout (Week 1)

Increase rollout to 10%. Monitor for errors and latency changes. If clean after
48 hours, move to 25%:

```yaml
migration:
  default-mode: BRIDGE
  rollout-percentage: 10      # 10% of bridge sessions use PQC
```

`/api/migration/status` will show approximately 10% `pqcMigrationPercent`.
Gradually increase: 10% → 25% → 50% → 75% → 100% over weeks.

---

### Scenario 3 — Per-Service Fast-Track and Hold-Back

Some services can migrate fast, some must wait for dependency reasons:

```yaml
migration:
  default-mode: BRIDGE
  rollout-percentage: 75
  service-overrides:
    # Legacy billing cannot migrate yet — 3rd party SDK requires RSA
    legacy-billing-svc: RSA_ONLY

    # Auth service is fully tested and signed off — lock it in
    auth-svc: PQC_ONLY

    # Payment service migrated by another team — also locked in
    payment-svc: PQC_ONLY
```

Result:
- `legacy-billing-svc` → always RSA (blocked by third-party constraint)
- `auth-svc` → always Kyber/HYBRID (fully migrated, no fallback possible)
- `payment-svc` → always Kyber/HYBRID (fully migrated)
- All other services → BRIDGE with 75% PQC / 25% RSA

---

### Scenario 4 — Full Migration Complete (Final State)

Once all services are ready, flip to PQC_ONLY globally. The RSA path disappears:

```yaml
migration:
  default-mode: PQC_ONLY      # All sessions use Kyber/Hybrid
  rollout-percentage: 100     # Redundant but explicit
```

At this point, `simulate-legacy` can still be used to verify that legacy
clients are handled gracefully (they will get PQC now — which only works if
they have been upgraded too). The bridge remains in place as a safety net
if you need to temporarily re-enable RSA for a single service via
`service-overrides`.

---

### Scenario 5 — Emergency Rollback

PQC is causing issues in production. Instantly fall back without redeployment
(requires Actuator or config reload to be set up):

```yaml
migration:
  default-mode: BRIDGE
  rollout-percentage: 0       # Back to all RSA immediately
```

No service restart needed if Spring Cloud Config or similar is in use.
The `rolloutPercentage` is read per-session, so taking effect on the next
request.

---

## Why These Design Decisions

### Why Reuse HandshakeSession Instead of a New Type

`HandshakeSession` already has everything needed: session key material, cipher
mode, algorithm metadata, `isQuantumSafe()`. Adding a new return type would
force every downstream consumer (encryption service, actuator, controller) to
handle a new type. Since the 32-byte session key is semantically identical
whether it came from RSA or Kyber, reusing `HandshakeSession` with
`classicalAlgorithm="RSA-2048-OAEP"` is the right abstraction.

### Why CipherMode.CLASSICAL for the RSA Path

`CipherMode.CLASSICAL` means "only classical algorithms, no PQC involvement".
RSA is a classical algorithm — it predates post-quantum cryptography by decades.
Using CLASSICAL correctly signals `quantumSafe=false` to all consumers without
adding a new enum value. If we added `RSA_LEGACY` it would break the existing
`isQuantumSafe()` contract on `CipherMode`.

### Why RSA-OAEP and Not RSA-PKCS1

RSA-PKCS1 v1.5 padding is vulnerable to Bleichenbacher's attack (1998). Any new
code that implements RSA should use OAEP. Even though the goal of Phase 5 is to
**replace** RSA, the RSA path must be correctly implemented during the migration
window — using broken padding would undermine the bridge's security guarantees.

### Why AtomicLong for Stats Counters

The bridge service is a singleton that handles concurrent HTTP requests. Using
`AtomicLong` (compare-and-swap, no lock contention) is the correct choice for
counters in a multi-threaded Spring context. Plain `long` would produce incorrect
stats under load. `synchronized` would create unnecessary bottlenecks.

### Why rolloutPercentage Uses SecureRandom

The routing decision (`rng.nextInt(100) < rolloutPercentage`) uses
`SecureRandom`, not `Random`. This is a cryptography library — using `Random`
(which is predictable if the seed is known) could allow an adversary to predict
which sessions will use RSA vs PQC and target accordingly. `SecureRandom` is
unpredictable.

---

## Test Coverage

| Test | Covers |
|------|--------|
| `rsaWrapUnwrapRoundTrip` | RSA-OAEP encrypt/decrypt recovers original 32 bytes |
| `rsaOaepIsRandomised` | OAEP is probabilistic — different ciphertext each call |
| `rsaOnlySessionMode` | RSA_ONLY → CLASSICAL cipher, not quantum-safe, RSA-2048-OAEP algo |
| `rsaOnlySessionHasId` | Session ID and clientId set correctly |
| `pqcOnlySessionMode` | PQC_ONLY → HYBRID cipher, quantum-safe, Kyber-768 algo |
| `bridgeFullRolloutAlwaysPqc` | BRIDGE + rollout=100% → all 5 sessions quantum-safe |
| `bridgeZeroRolloutAlwaysRsa` | BRIDGE + rollout=0% → all 5 sessions RSA fallback |
| `perServiceOverrideForcesRsa` | Override `RSA_ONLY` wins over global `PQC_ONLY` default |
| `perServiceOverrideForcesPqc` | Override `PQC_ONLY` wins over global `RSA_ONLY` default |
| `statsTrackSessionCounts` | 2 RSA + 3 PQC → total=5, migrated=60%, quantum-safe=3 |

---

## New Files Summary

| Class | Role |
|-------|------|
| `MigrationMode` | Enum: `RSA_ONLY`, `BRIDGE`, `PQC_ONLY` |
| `MigrationStats` | Record: session counts + `pqcMigrationPercent` |
| `RsaKeyConverter` | RSA-2048 keypair + OAEP `wrapKeyMaterial` / `unwrapKeyMaterial` |
| `RsaKyberBridgeService` | Core: mode resolution, RSA/PQC routing, AtomicLong stats |
| `RsaMigrationProperties` | `@ConfigurationProperties` for rollout% + overrides |
| `RsaMigrationAutoConfiguration` | `@AutoConfiguration` bean wiring |
| `RsaMigrationController` | REST: `/bridge-handshake`, `/simulate-*`, `/status`, `/rsa-public-key` |
| `RsaMigrationBridgeTest` | 10 unit tests — no Spring context required |
