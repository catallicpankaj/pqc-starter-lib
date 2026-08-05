# Architecture

> How the six completed phases fit together as one system: layering, request lifecycle,
> module boundaries, cross-cutting design patterns, and where to extend it.

For the per-phase deep dives this document summarizes, see
[Phase1](Phase1Implementation.md), [Phase2](Phase2Implementation.md),
[Phase3](Phase3Implementation.md), [Phase4](Phase4ImplementationDetails.md),
[Phase5](Phase5ImplementationDetails.md), [Phase6](Phase6ImplementationDetails.md).

---

## Layered System View

```
┌──────────────────────────────────────────────────────────────────────────┐
│  YOUR APPLICATION                                                        │
│  @Autowired PqcEncryptionService / DilithiumSigningEngine / etc.         │
└───────────────────────────────────┬────────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────────┐
│  PHASE 4/5/6 — Application-Facing Modules  (each independently toggleable) │
│                                                                             │
│  JWT (auth layer)      RSA Migration Bridge      Data at Rest              │
│  DilithiumJwtService    RsaKyberBridgeService     AtRestEncryptionService  │
│  DilithiumJwtFilter     RsaKeyConverter           EncryptedFieldService    │
│  pqc.jwt.*       pqc.migration.*    StreamingAesGcmEngine   │
│                                                    pqc.atrest.*     │
└──────────────┬──────────────────────┬──────────────────────┬──────────────┘
              │                      │                      │
              ▼                      ▼                      ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  PHASE 3 — Key Management  (optional — activates on pqc.key-      │
│                              management.provider being set)              │
│                                                                            │
│  QuantumKeyService → KeyManagementProvider (Strategy) → KeyRegistry      │
│  local | hashicorp-vault | aws-kms | azure-key-vault | gcp-kms           │
└───────────────────────────────────┬────────────────────────────────────────┘
                                    │  Optional<QuantumKeyService>
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  PHASE 2 — Spring Boot Integration                                       │
│                                                                            │
│  HybridHandshakeFilter → HybridHandshakeOrchestrator → PqcEncryptionService│
│  AesGcmEngine    PqcActuatorEndpoint    PqcAutoConfiguration              │
└───────────────────────────────────┬────────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────────┐
│  PHASE 1 — Core Cryptography Engine  (no Spring/HTTP dependency)          │
│                                                                            │
│  KyberKemEngine (FIPS 203)   DilithiumSigningEngine (FIPS 204)            │
│  SphincsSigningEngine (FIPS 205)   ECDHE-P384 (classical, via JCA)        │
└──────────────────────────────────────────────────────────────────────────┘
```

**Dependency direction is strictly downward.** Phase 1 has zero knowledge of Phase 2 or above.
Phase 2 depends on Phase 1 and *optionally* on Phase 3 (`Optional<QuantumKeyService>` — absent
means ephemeral keys, present means KMS-managed persistent keys, with no code branching required
by the caller). Phases 4/5/6 each depend on Phase 1/2 directly and are otherwise independent of
each other — you can run any subset of them; each has its own `enabled` property and its own
`@AutoConfiguration` class.

---

## Module Boundaries and Auto-Configuration

Four `@AutoConfiguration` classes, each independently toggleable, each discovered via
`META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`:

| Auto-configuration | Toggle property | Default | Owns |
|---|---|---|---|
| `PqcAutoConfiguration` | `pqc.enabled` | `true` | Handshake, encryption, signing engines, JWT beans |
| `KeyManagementAutoConfiguration` | `pqc.key-management.provider` (presence, not boolean) | unset = disabled | KMS provider, `QuantumKeyService`, key rotation |
| `RsaMigrationAutoConfiguration` | `pqc.migration.enabled` | `true` | RSA↔Kyber bridge, `/api/migration/*` |
| `AtRestEncryptionAutoConfiguration` | `pqc.atrest.enabled` | `true` | Field/file encryption, `/api/atrest/*` |

This split matters for two reasons:

1. **Independent toggling.** You can run this library with only the handshake/encryption core
   active (`pqc.enabled=true`, everything else default-off-by-absence or explicitly
   disabled) — the JWT auth demo, migration bridge, and at-rest REST surface are not forced on you
   as a package deal.
2. **Every bean is `@ConditionalOnMissingBean`.** If your application defines its own bean of a
   type this library also provides, yours wins and only that one bean backs off — the rest of the
   auto-configuration still applies.

The one auto-configuration class that is conditioned on **presence of a property value** rather
than a boolean is `KeyManagementAutoConfiguration`
(`@ConditionalOnProperty(prefix = "pqc.key-management", name = "provider")` — no
`havingValue`, so *any* non-empty value activates it). This is intentional: there's no sensible
default KMS provider, so the feature is opt-in by configuring one, not by flipping a boolean.

---

## Request Lifecycle (HTTP Path)

```
Incoming HTTP request
       │
       ▼
┌─────────────────────────────┐
│ Spring Security filter chain │  ← present only if a SecurityFilterChain bean exists
│ (springSecurityFilterChain)  │    (this library's own SecurityConfig, or your own)
└──────────────┬───────────────┘
              │ (if permitted / authenticated)
              ▼
┌─────────────────────────────┐
│ HybridHandshakeFilter        │  ← auto-registered raw servlet Filter, @Order(1)
│ (Phase 2)                    │    runs regardless of Spring Security's decision on
└──────────────┬───────────────┘    this request UNLESS Security already rejected it
              │
              ▼
┌─────────────────────────────┐
│ DilithiumJwtFilter            │  ← also a raw Filter bean AND (if SecurityConfig
│ (Phase 4)                     │    is present) chained inside Spring Security via
└──────────────┬───────────────┘    addFilterBefore(...) — see note below
              │
              ▼
┌─────────────────────────────┐
│ DispatcherServlet             │
│ → your @RestController        │
│   or this library's demo/     │
│   auto-registered controllers │
└───────────────────────────────┘
```

**Filter double-registration nuance:** both `HybridHandshakeFilter` and `DilithiumJwtFilter` are
plain `@Bean`-registered `Filter` implementations, which Spring Boot auto-registers as raw servlet
filters (default `/*` mapping) independent of Spring Security. `DilithiumJwtFilter` is *also*
wired into the Spring Security chain via `SecurityConfig.filterChain()`'s
`addFilterBefore(dilithiumJwtFilter, UsernamePasswordAuthenticationFilter.class)` — but only when
`SecurityConfig` is present (component-scanned), which — per
[the README's integration section](../README.md#integrating-into-an-existing-spring-boot-app) —
is **not** the case when this library is consumed as a dependency in an app with a different base
package. In that situation `DilithiumJwtFilter` still runs (as a raw filter) but isn't tied into
Spring Security's authentication context — it can still validate/reject tokens on its own, but
`SecurityContextHolder` population/enforcement is whatever your own security configuration does
with the result.

---

## Data Flow: What Actually Gets Encrypted, With What Key

```
                    ┌───────────────────────────────────────┐
                    │  Session-scoped data (Phase 1/2)        │
                    │  key: HYBRID/PQC_ONLY/CLASSICAL          │
                    │  KDF over ECDHE + Kyber secrets          │
                    │  lifetime: until JVM restart or          │
                    │  session cache eviction (in-memory only) │
                    └───────────────────────────────────────┘
                                     │ optionally backed by
                                     ▼
                    ┌───────────────────────────────────────┐
                    │  Persistent identity keys (Phase 3)      │
                    │  kyber-server-key / ec-server-key /      │
                    │  dilithium-signing-key                    │
                    │  survive restarts, rotate on schedule,    │
                    │  wrapped by a KMS/Vault master key that   │
                    │  never leaves the KMS                    │
                    └───────────────────────────────────────┘

                    ┌───────────────────────────────────────┐
                    │  Record-scoped data (Phase 6)            │
                    │  key: HKDF-SHA256(masterKey,             │
                    │        salt=recordId,                     │
                    │        info="fieldName:keyVersion")       │
                    │  independent of the handshake entirely —  │
                    │  no session, no orchestrator involved     │
                    └───────────────────────────────────────┘
```

These are **three separate key hierarchies that do not share key material.** A compromised
session key (Phase 1/2, in-memory, ephemeral) does not expose the Phase 3 identity keys or the
Phase 6 per-record keys, and vice versa. This is deliberate — it bounds the blast radius of any
one compromise to the layer it occurred in.

---

## Cross-Cutting Design Patterns

| Pattern | Where it appears | Why |
|---|---|---|
| **Strategy** | `KeyManagementProvider` (5 implementations), `CipherMode`-driven handshake dispatch, `MigrationMode`-driven session routing | Swap the algorithm/backend without touching the caller |
| **Facade** | `PqcEncryptionService`, `AtRestEncryptionService` | One simple entry point over several collaborating internal classes |
| **Optional dependency injection** | `HybridHandshakeOrchestrator(Optional<QuantumKeyService>)`, `DilithiumKeyPairHolder(Optional<QuantumKeyService>)` | Phase 3 is additive — its absence doesn't break Phase 1/2/4, it just means ephemeral keys |
| **Auto-configuration + `@ConditionalOnMissingBean`** | All four `@AutoConfiguration` classes | Every bean is a sensible default that a consuming app can override individually |
| **Versioned registry** | `KeyRegistry` (ACTIVE/DEPRECATED/RETIRED lifecycle) | Old key versions stay available for decrypting existing data through a rotation, without blocking new writes onto the new version |
| **Record-based DTOs** | `HandshakeSession.SessionSummary`, `KemResult`, `EncryptedPayload`, `MigrationStats`, `WrappedKeyMaterial` | Immutable, no-boilerplate value carriers — several deliberately never expose raw key material (`toSummary()` methods) |

---

## Extension Points

**Add a new KMS provider (Phase 3):** implement `KeyManagementProvider`, add one `@Bean` method
to `KeyManagementAutoConfiguration` guarded by
`@ConditionalOnProperty(name = "pqc.key-management.provider", havingValue = "your-provider")`,
add a config nested class to `KeyManagementProperties`. No other file changes — `QuantumKeyService`,
`HybridHandshakeOrchestrator`, and `KeyRotationManager` all work with any provider automatically.
Full walkthrough (Thales HSM example) in [Phase3Implementation.md](Phase3Implementation.md#adding-a-new-provider).

**Add a new signing algorithm:** follow `DilithiumSigningEngine`/`SphincsSigningEngine`'s shape —
`generateKeyPair()`/`sign()`/`verify()` over a JCA `Signature` instance against the `BCPQC`
provider — then register it as a `@Bean` in `PqcAutoConfiguration` alongside the existing two.

**Add a new `EncryptedAttributeConverter` subclass (Phase 6):** provide `getService()`,
`getFieldName()`, and optionally `getRecordId()` — see the `SsnConverter` example in
[Phase6ImplementationDetails.md](Phase6ImplementationDetails.md).

---

## Known Gaps and Dead Code

Documented here rather than silently left for someone to discover the hard way:

- **`PqcProperties` (`com.pqc.hybrid.config.PqcProperties`) is unused.** It declares
  `pqc.preferred-mode`, `pqc.allow-classical-fallback`, and
  `pqc.session-cache-size` properties, but the class is never registered via
  `@EnableConfigurationProperties` and never injected anywhere. Setting these three properties in
  `application.yml` has **no effect** — actual mode negotiation is entirely client-driven, via the
  `X-PQC-Supported`/`X-PQC-Hybrid` headers parsed by `HybridHandshakeFilter` and
  `ClientCapability.negotiateBestMode()`. If you need a server-side default/ceiling on negotiated
  mode, it isn't implemented yet.
- **`/actuator/pqc` does not report Phase 3 key-management status** (provider name, key versions,
  health) despite this being documented as a feature in an earlier revision of
  `Phase3Implementation.md` (now corrected). Inject `KeyRegistry` or `QuantumKeyService` directly
  if you need that visibility.
- **`hybridKdf()`/`simpleKdf()`** (`HybridHandshakeOrchestrator`) use a single-shot HMAC-SHA256
  rather than a textbook HKDF-Extract-and-Expand — cryptographically sound but not RFC 5869. A
  proper HKDF implementation already exists in this codebase (`HkdfKeyDerivation`, used by Phase
  6) and would be the natural thing to swap in for a production hardening pass.
- **Handshake "round trips" are simulated in a single JVM.** `performHybridHandshake()` and
  friends call both the encapsulating and decapsulating sides within the same method, on the same
  server instance — there is no real network round trip modeled. This is sufficient to prove the
  cryptography (and is what the test suite exercises), but a real two-service deployment would
  need the ciphertext to actually cross the wire, which none of the current controllers do.
