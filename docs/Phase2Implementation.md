# Phase 2 — Spring Boot Integration + Data Encryption: Implementation Guide

> Wires Phase 1's crypto primitives into a usable Spring Boot library: AES-256-GCM data
> encryption keyed off the hybrid session, a servlet filter for per-request mode negotiation,
> and auto-configuration so every bean is available with zero manual wiring.

---

## Scope

Phase 2 answers the question Phase 1 leaves open: **the handshake produces a session key — now
what?** This phase plugs that key into real AES-256-GCM data encryption, exposes everything as
Spring beans via auto-configuration, and adds a servlet filter that performs the handshake
automatically on every incoming request based on `X-PQC-*` headers.

**What's in scope:** `AesGcmEngine` (symmetric encryption), `PqcEncryptionService` (the
top-level API your code calls), `HybridHandshakeFilter` (per-request mode negotiation),
`PqcAutoConfiguration` (bean wiring), `PqcActuatorEndpoint` (`/actuator/pqc`), and the demo
REST controllers.

**What's explicitly out of scope:** persistent keys (Phase 3), JWT (Phase 4), RSA
interoperability (Phase 5), database/file encryption (Phase 6) — this phase encrypts in-flight
session data only.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│  HTTP Request                                                            │
└───────────────────────────────┬───────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  HybridHandshakeFilter  (@Order(1), runs before Spring MVC dispatch)     │
│  parses X-PQC-* headers → orchestrator.orchestrate()/.upgradeSession()  │
│  attaches HandshakeSession to request attributes                        │
│  writes X-PQC-Mode / X-PQC-Session-Id / X-PQC-Quantum-Safe response hdrs│
└───────────────────────────────┬───────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Your controller / service                                               │
│  @Autowired PqcEncryptionService pqcEncryption;                          │
│                                                                            │
│  pqcEncryption.establishHybridSession(clientId)                          │
│  pqcEncryption.encryptForSession(sessionId, plaintext)                   │
│  pqcEncryption.decryptForSession(sessionId, ciphertext)                  │
└───────────────┬───────────────────────────────────┬───────────────────────┘
                │                                   │
                ▼                                   ▼
   ┌─────────────────────────┐       ┌───────────────────────────────┐
   │  HybridHandshakeOrchestrator │   │  AesGcmEngine                  │
   │  (Phase 1)                │   │  AES-256-GCM encrypt/decrypt,   │
   │  → HandshakeSession        │   │  Base64 wire (de)serialization  │
   └─────────────────────────┘       └───────────────────────────────┘
```

### Design Patterns Used

| Pattern | Where | Why |
|---|---|---|
| **Facade** | `PqcEncryptionService` | One simple API (`establish*Session`, `encryptForSession`, `decryptForSession`) hides the orchestrator + AES engine wiring underneath |
| **Chain of Responsibility** | `HybridHandshakeFilter` (servlet `Filter`) | Standard servlet filter chain — runs before any controller, independent of which endpoint is hit |
| **Auto-configuration (conditional)** | `PqcAutoConfiguration` | `@ConditionalOnClass`/`@ConditionalOnProperty`/`@ConditionalOnMissingBean` — activates automatically, and every bean is overridable by a user-supplied bean of the same type |
| **Record (DTO)** | `AesGcmEngine.EncryptedPayload`, `PqcEncryptionService.PipelineResult` | Immutable carriers for encryption output and end-to-end demo results |

---

## Package Structure

```
com.pqc.hybrid.crypto/
├── AesGcmEngine.java            ← AES-256-GCM encrypt/decrypt, Base64 wire format
└── PqcEncryptionService.java    ← top-level facade: session + encrypt + decrypt

com.pqc.hybrid.filter/
└── HybridHandshakeFilter.java   ← per-request mode negotiation (servlet Filter)

com.pqc.hybrid.actuator/
└── PqcActuatorEndpoint.java     ← /actuator/pqc — status, sessions, algorithms, benchmark

com.pqc.hybrid.autoconfigure/
└── PqcAutoConfiguration.java    ← Spring Boot auto-configuration — wires every bean above

com.pqc.hybrid.controller/
├── PqcDemoController.java       ← /api/pqc/* — handshake + signing demos
└── EncryptionDemoController.java ← /api/encrypt/* — full encrypt/decrypt pipeline demos
```

---

## AES-256-GCM Engine (`AesGcmEngine`)

The session key produced by Phase 1's handshake — 32 bytes, regardless of which of the three
modes negotiated it — becomes the AES-256 key here. `AesGcmEngine` is deliberately narrow: encrypt,
decrypt, and Base64 wire (de)serialization, nothing else.

```
Wire format:
┌─────────────────────────────────────────────────┐
│  IV (12 bytes)  │  Ciphertext + GCM Tag (N+16)  │
└─────────────────────────────────────────────────┘
```

```java
public EncryptedPayload encrypt(byte[] sessionKey, byte[] plaintext, String sessionId) {
    byte[] iv = new byte[12];
    secureRandom.nextBytes(iv);                                   // fresh IV every call
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
    cipher.init(ENCRYPT_MODE, new SecretKeySpec(sessionKey, "AES"), new GCMParameterSpec(128, iv));
    cipher.updateAAD(sessionId.getBytes());                       // AAD, not encrypted, but authenticated
    byte[] ciphertextWithTag = cipher.doFinal(plaintext);
    return new EncryptedPayload(iv, ciphertextWithTag, sessionId);
}
```

Three properties, all enforced by the code (not just documented):

- **Fresh IV per call.** `secureRandom.nextBytes(iv)` runs on every `encrypt()` invocation — the
  same key never reuses an IV. `AesGcmEngineTest` verifies 100 consecutive encryptions produce 100
  unique IVs.
- **Tamper detection is automatic, not opt-in.** Any single-bit flip in the ciphertext (or the
  GCM tag) causes `cipher.doFinal()` to throw `AEADBadTagException` on decrypt — there is no
  separate "verify" step to forget to call.
- **AAD binds ciphertext to its session.** `sessionId` is passed as GCM's Additional
  Authenticated Data — it's not encrypted (visible in cleartext if you inspect the call), but it
  *is* authenticated, so decrypting under a different `sessionId` than the one used at encrypt
  time fails the tag check even with the correct key. This stops an attacker from copying a valid
  ciphertext from session A into session B.

`validateKey()` rejects any key that isn't exactly 32 bytes before touching the `Cipher` — a
malformed or truncated session key fails fast with `IllegalArgumentException` rather than a
confusing JCA exception three frames deeper.

### Serialization

`toBase64Wire()`/`fromBase64Wire()` concatenate `IV || ciphertextWithTag` and Base64-encode the
result — one string, safe to put in JSON or an HTTP header. `EncryptedPayload.plaintextBytes()` is
a convenience that subtracts the fixed 16-byte GCM tag from the wire length to report the original
payload size without decrypting.

---

## `PqcEncryptionService` — The Facade Your Code Actually Calls

```java
HandshakeSession session = pqcEncryption.establishHybridSession("my-client");
String encrypted = pqcEncryption.encryptForSession(session.getSessionId(), "secret data");
String decrypted = pqcEncryption.decryptForSession(session.getSessionId(), encrypted);
```

Three constructor-injected dependencies: `HybridHandshakeOrchestrator` (Phase 1) and
`AesGcmEngine`. Everything else is a thin method that:

1. Looks up the cached session by ID (`getSessionOrThrow` — throws `IllegalStateException` with
   a clear "establish a session first" message if the ID is unknown), and
2. Delegates to `orchestrator` for handshake operations or `aesGcm` for encrypt/decrypt, and
3. Converts to/from the Base64 wire format so callers never touch raw byte arrays.

### Encrypt Flow

```
  Caller           PqcEncryptionService         HybridHandshakeOrchestrator      AesGcmEngine
    │                       │                              │                          │
    │  encryptForSession(   │                              │                          │
    │    sessionId,         │                              │                          │
    │    plaintext)         │                              │                          │
    │──────────────────────►│                              │                          │
    │                       │  getSession(sessionId)        │                          │
    │                       │─────────────────────────────►│                          │
    │                       │◄──── HandshakeSession ────────│                          │
    │                       │                              │                          │
    │                       │  encryptString(               │                          │
    │                       │    session.sessionKeyMaterial,│                          │
    │                       │    plaintext, sessionId)      │                          │
    │                       │───────────────────────────────────────────────────────► │
    │                       │◄──── EncryptedPayload(iv, ciphertextWithTag) ─────────── │
    │                       │                              │                          │
    │                       │──┐ toBase64Wire()             │                          │
    │                       │◄─┘                            │                          │
    │  Base64 ciphertext    │                              │                          │
    │◄──────────────────────│                              │                          │
```

Decrypt is the mirror image: `fromBase64Wire()` splits the string back into `iv` +
`ciphertextWithTag`, then `aesGcm.decryptString()` runs the GCM tag check and returns plaintext —
or throws if the AAD, key, or ciphertext don't match what was used to encrypt.

### `runEndToEndPipeline()` — Convenience for Testing/Demos

Establishes a HYBRID session, encrypts, decrypts, and verifies the round trip in one call,
returning a `PipelineResult` record with timing and byte-count metadata. This is what
`EncryptionDemoController`'s `/api/encrypt/e2e` endpoint calls — the single best endpoint to hit
first when proving the whole chain works end to end.

---

## `HybridHandshakeFilter` — Per-Request Mode Negotiation

A plain servlet `Filter` (`@Component`, `@Order(1)`), not a Spring Security filter — it runs
before Spring MVC dispatch on **every** request, regardless of route.

```
  HTTP Request                HybridHandshakeFilter          HybridHandshakeOrchestrator
      │                              │                                 │
      │  GET /api/pqc/status         │                                 │
      │  X-PQC-Supported: Kyber-768,Dilithium-3                        │
      │  X-PQC-Hybrid: true          │                                 │
      │─────────────────────────────►│                                 │
      │                              │──┐ parseCapability(request)      │
      │                              │  │ → ClientCapability             │
      │                              │◄─┘                              │
      │                              │                                 │
      │                              │  X-PQC-Session header present?   │
      │                              │  no  → orchestrate(capability)   │
      │                              │  yes → upgradeSession(id, cap)   │
      │                              │────────────────────────────────►│
      │                              │◄──────── HandshakeSession ───────│
      │                              │                                 │
      │                              │  request.setAttribute(           │
      │                              │    "pqc.session", session)       │
      │                              │                                 │
      │                              │  response headers:               │
      │                              │    X-PQC-Mode: HYBRID            │
      │                              │    X-PQC-Session-Id: ...         │
      │                              │    X-PQC-Quantum-Safe: true      │
      │                              │                                 │
      │                              │  chain.doFilter() → continue to  │
      │                              │  Spring MVC dispatch              │
```

On any exception during handshake (malformed headers, orchestrator failure), the filter **does
not fail the request** — it catches the exception, logs a warning, sets
`X-PQC-Mode: CLASSICAL` / `X-PQC-Fallback: true` / `X-PQC-Quantum-Safe: false`, and still calls
`chain.doFilter()`. A broken PQC negotiation degrades to "no session attached," it never 500s the
request.

Downstream code (a controller, another filter) can read the negotiated session via
`request.getAttribute(HybridHandshakeFilter.ATTR_SESSION)` — `PqcDemoController`'s `/api/pqc/status`
endpoint does exactly this to report the negotiated mode without doing its own handshake.

**Auto-registration note:** because `HybridHandshakeFilter` is a plain `Filter`-typed Spring bean,
Spring Boot automatically registers it in the servlet container with the standard default mapping
(`/*`) — no manual `FilterRegistrationBean` needed, and this applies whether or not
`PqcDemoController`/`SecurityConfig` are present in the consuming application. See
[Integrating Into an Existing Spring Boot App](../README.md#integrating-into-an-existing-spring-boot-app)
in the README for what this means when this library is added as a dependency elsewhere.

---

## Auto-Configuration (`PqcAutoConfiguration`)

```java
@AutoConfiguration
@ConditionalOnClass({ BouncyCastleProvider.class, BouncyCastlePQCProvider.class })
@ConditionalOnProperty(prefix = "pqc", name = "enabled", havingValue = "true", matchIfMissing = true)
public class PqcAutoConfiguration {
    // one @Bean @ConditionalOnMissingBean method per bean below
}
```

| Bean | Notes |
|---|---|
| `HybridHandshakeOrchestrator` | Injects `Optional<QuantumKeyService>` — falls back to ephemeral keys when Phase 3 isn't configured |
| `HybridHandshakeFilter` | Depends on the orchestrator bean above |
| `AesGcmEngine` | No dependencies |
| `PqcEncryptionService` | Depends on both `HybridHandshakeOrchestrator` and `AesGcmEngine` |
| `DilithiumSigningEngine` / `SphincsSigningEngine` | No dependencies |
| `PqcActuatorEndpoint` | Depends on the orchestrator bean + `Optional<QuantumKeyService>` |
| `DilithiumKeyPairHolder` / `DilithiumJwtService` / `DilithiumJwtFilter` / `DilithiumJwtAuthController` | Phase 4 beans — also wired here since JWT is part of the same `pqc.enabled` toggle |

Every method is `@ConditionalOnMissingBean` — if the consuming application defines its own bean of
the same type, that bean wins and this auto-configuration backs off for that one bean only. This
is discovered by Spring Boot via
`META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`, which is
picked up automatically for **any** application that has this JAR on the classpath — it does not
depend on the consuming application's package structure or `@ComponentScan` configuration.

Contrast this with `PqcDemoController`, `EncryptionDemoController`, and `SecurityConfig` — those
are plain `@RestController`/`@Configuration` classes with no corresponding `@Bean` method in any
`@AutoConfiguration` class, so they rely on classpath component scanning and only activate when
this repository's own `PqcStarterLibApplication` runs. See
[Integrating Into an Existing Spring Boot App](../README.md#integrating-into-an-existing-spring-boot-app)
for the full breakdown of what does and doesn't carry over into a consuming application, verified
empirically against a real host app in a different package.

---

## `PqcActuatorEndpoint` — `/actuator/pqc`

```
GET  /actuator/pqc              — full status report
GET  /actuator/pqc/sessions     — active session summaries (no key material)
GET  /actuator/pqc/algorithms   — which algorithms are available on this JVM/provider
POST /actuator/pqc               — runs a 20-iteration benchmark across all 3 modes, returns avg ms
```

`algorithmStatus()` doesn't hardcode "yes, these work" — it actually probes each algorithm via
`KeyPairGenerator.getInstance(algo, provider)` (falling back to `Mac.getInstance` for
`HmacSHA256-KDF`) and reports `available: true/false` based on whether the JCA lookup succeeds.
This means a broken BouncyCastle install, a mismatched Java version, or a missing provider
registration shows up directly in the actuator response rather than as a downstream `sign()`
failure with no obvious cause.

> When Phase 3 is configured, this endpoint's response also includes a `keyManagement` block
> (provider name, health, per-key version history) via `Optional<QuantumKeyService>` injection —
> `null` when Phase 3 isn't active. See
> [`Phase3Implementation.md`](Phase3Implementation.md#actuator-integration) for the response shape.

---

## Demo Controllers

`PqcDemoController` (`/api/pqc/*`) and `EncryptionDemoController` (`/api/encrypt/*`) exist to make
every Phase 1/2 capability curl-able without writing any code. They are genuinely useful for
learning the library and for local development, but — as covered in the README's integration
section — they are **not** part of the auto-configured surface: they only exist when this
repository's own demo application runs.

The most useful individual endpoints:

| Endpoint | What it proves |
|---|---|
| `GET /api/pqc/status` | Shows the negotiated `CipherMode` for the current request (reads the filter's request attribute) |
| `GET /api/pqc/upgrade-demo` | CLASSICAL → HYBRID upgrade without reconnecting |
| `POST /api/encrypt/e2e` | Full pipeline: handshake → encrypt → decrypt → verify, one call |
| `POST /api/encrypt/tamper-test` | Flips a bit in a real ciphertext and proves GCM rejects it |
| `GET /api/encrypt/compare-modes` | Encrypts the same payload under all three modes side by side — proves ciphertext size doesn't change, only key derivation does |

`EncryptionDemoController`'s step-by-step endpoints (`/session`, `/encrypt`, `/decrypt`) take a
JSON body, not query parameters — e.g. `POST /api/encrypt/encrypt` with body
`{"sessionId":"...","plaintext":"..."}`, not `?data=...`. See the README's Quick Start for
corrected, tested curl commands.

---

## Test Coverage

| Test class | What it covers |
|---|---|
| `AesGcmEngineTest` (13 tests) | Encrypt/decrypt round-trip, tamper rejection, wrong-session rejection, wrong-key rejection, IV uniqueness across 100 runs, non-determinism, key-length validation, wire format round-trip |
| `HybridOrchestratorIntegrationTest` (7 tests) | `PqcEncryptionService` end-to-end for all 3 modes, session isolation, upgrade path |

```bash
mvn test -Dtest=AesGcmEngineTest,HybridOrchestratorIntegrationTest
```

---

## What Phase 2 Enables (and Doesn't)

```
Client                              Server
──────                              ──────
1. Handshake (Kyber + ECDHE)   →   Derive shared session key
2. sessionKey = KDF(secrets)   =   sessionKey (same on both sides)
3. AES-256-GCM encrypt(data)   →   AES-256-GCM decrypt(data)
```

**Current limitation, resolved by Phase 3:** session keys live in JVM heap memory only —
`HybridHandshakeOrchestrator`'s session cache is a plain `ConcurrentHashMap`, not backed by any
store. A server restart makes every previously established session key (and anything encrypted
under it) unrecoverable. This makes Phase 2 suitable for in-flight session encryption but not, on
its own, for persistent data-at-rest encryption — see
[Phase 3](Phase3Implementation.md) for KMS-backed key persistence and
[Phase 6](Phase6ImplementationDetails.md) for the data-at-rest tooling built on top of it.
