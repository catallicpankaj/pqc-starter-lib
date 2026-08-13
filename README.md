# PqcStarterLib

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Java 17+](https://img.shields.io/badge/Java-17%2B-orange.svg)](#requirements)
[![Spring Boot 4.1+](https://img.shields.io/badge/Spring%20Boot-4.1%2B-brightgreen.svg)](#requirements)

> A Spring Boot starter for **Hybrid Classical + Post-Quantum Cryptography**. Implements real
> Kyber-768 (ML-KEM), Dilithium-3 (ML-DSA), and SPHINCS+ (SLH-DSA) with runtime switching between
> `CLASSICAL`, `PQC_ONLY`, and `HYBRID` modes — protecting applications against both today's and
> tomorrow's ("harvest now, decrypt later") threats.

Drop it into any Spring Boot application as a dependency and get quantum-resistant key exchange,
authenticated encryption, JWT signing, KMS-backed key management, gradual RSA migration, and
transparent data-at-rest encryption — with sane defaults and zero required configuration to start.

---

## Table of Contents

- [Why PqcStarterLib](#why-pqcstarterlib)
- [Features at a Glance](#features-at-a-glance)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Integrating Into an Existing Spring Boot App](#integrating-into-an-existing-spring-boot-app)
- [Configuration Reference](#configuration-reference)
- [Feature Guide](#feature-guide)
  - [Hybrid Handshake](#1-hybrid-handshake)
  - [AES-256-GCM Data Encryption](#2-aes-256-gcm-data-encryption)
  - [Key Management (KMS / Vault)](#3-key-management-kms--vault)
  - [Dilithium-3 Signed JWT](#4-dilithium-3-signed-jwt)
  - [RSA Migration Bridge](#5-rsa-migration-bridge)
  - [Data at Rest (JPA + File Encryption)](#6-data-at-rest-jpa--file-encryption)
- [Algorithms Implemented](#algorithms-implemented-real-not-simulated)
- [Verified Performance](#verified-performance)
- [Runtime Switching Protocol](#runtime-switching-protocol)
- [Project Structure](#project-structure)
- [Running Tests](#running-tests)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

---

## Why PqcStarterLib

Cryptographically relevant quantum computers will eventually break RSA and ECC. Attackers already
practice **"harvest now, decrypt later"**: capture today's encrypted traffic and data, then decrypt
it once a quantum computer is available. Any data that must stay confidential for years — health
records, financial data, long-lived credentials — is exposed under that model *today*, even though
the quantum computer doesn't exist yet.

PqcStarterLib closes that gap now by:

- Implementing the finalized **NIST 2024 PQC standards** (FIPS 203/204/205) using BouncyCastle —
  not toy or simulated crypto.
- Running **hybrid mode by default**: classical (ECDHE-P384) and post-quantum (Kyber-768) key
  material are combined, so an attacker must break *both* to compromise a session.
- Supporting **gradual, per-service migration** from RSA instead of forcing a hard cut-over.
- Providing **transparent data-at-rest encryption** for JPA entities and files with per-record
  key isolation.
- Requiring **no code changes to adopt** — add the dependency, get sane defaults, override only
  what you need.

---

## Features at a Glance

| Capability | What you get |
|---|---|
| **Hybrid handshake** | ECDHE-P384 + Kyber-768 combined session keys, runtime mode negotiation per client |
| **Authenticated encryption** | AES-256-GCM with fresh IVs, tamper detection, session-bound AAD |
| **Key management** | Pluggable KMS strategy — local dev, HashiCorp Vault, AWS/Azure/GCP (stubs) |
| **Quantum-safe JWT** | Dilithium-3 signed tokens, drop-in for existing Spring Security setups |
| **RSA migration bridge** | `RSA_ONLY` / `BRIDGE` / `PQC_ONLY` modes with per-service overrides and rollout % |
| **Data at rest** | Field-level JPA encryption + chunked streaming file encryption, HKDF key isolation |
| **Zero-config start** | Every feature works with ephemeral keys and safe defaults out of the box |

---

## Requirements

- Java 17+
- Spring Boot 4.1+
- BouncyCastle 1.78.1+ (`bcprov-jdk18on`, `bcpkix-jdk18on`) — pulled in transitively

---

## Installation

PqcStarterLib is not yet published to Maven Central. Until then, build and install it into your
local repository, or consume it directly from source via [JitPack](https://jitpack.io).

### Option A — Install locally

```bash
git clone https://github.com/your-org/pqc-starter-lib.git
cd pqc-starter-lib
mvn install
```

Then add it to your project:

**Maven**

```xml
<dependency>
  <groupId>com.pqc</groupId>
  <artifactId>pqc-starter-lib</artifactId>
  <version>1.0.0-SNAPSHOT</version>
</dependency>
<dependency>
  <groupId>org.bouncycastle</groupId>
  <artifactId>bcprov-jdk18on</artifactId>
  <version>1.78.1</version>
</dependency>
```

**Gradle**

```groovy
dependencies {
    implementation 'com.pqc:pqc-starter-lib:1.0.0-SNAPSHOT'
    implementation 'org.bouncycastle:bcprov-jdk18on:1.78.1'
}
```

### Option B — JitPack (build from a GitHub tag/commit, no local install)

```xml
<repositories>
  <repository>
    <id>jitpack.io</id>
    <url>https://jitpack.io</url>
  </repository>
</repositories>

<dependency>
  <groupId>com.github.your-org</groupId>
  <artifactId>pqc-starter-lib</artifactId>
  <version>main-SNAPSHOT</version> <!-- or a tagged release -->
</dependency>
```

Spring Boot auto-discovers PqcStarterLib's auto-configuration classes via
`META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports` — no manual
`@Import` or `@EnableXxx` annotation required.

---

## Quick Start

### 1. Add the dependency

See [Installation](#installation) above.

### 2. Configure (optional — defaults work out of the box)

```yaml
pqc:
  enabled: true                        # default: true

  # JWT settings (defaults shown)
  jwt:
    ttl-minutes: 60
    demo-password: secret              # change in production

  # Key Management (comment out to use ephemeral keys)
  # key-management:
  #   provider: local
  #   local:
  #     key-store-path: ${user.home}/.pqc-starter-lib/local-master.key
  #     auto-generate: true

  # RSA Migration Bridge (defaults work out of the box)
  # migration:
  #   default-mode: BRIDGE           # RSA_ONLY | BRIDGE | PQC_ONLY
  #   rollout-percentage: 100        # 0–100%: BRIDGE sessions routed to PQC
  #   service-overrides:
  #     legacy-svc: RSA_ONLY
  #     migrated-svc: PQC_ONLY

  # Data at Rest (defaults work out of the box)
  # atrest:
  #   master-key-hex: ""             # 64 hex chars; auto-random if blank (dev only)
  #   master-key-version: 1          # increment after key rotation
  #   chunk-size: 4096               # streaming chunk size in bytes
```

### 3. Use it in your code

```java
// Handshake + encryption
@Autowired HybridHandshakeOrchestrator orchestrator;
@Autowired PqcEncryptionService pqcEncryption;

HandshakeSession session = pqcEncryption.establishHybridSession("my-client");
String encrypted = pqcEncryption.encryptForSession(session.getSessionId(), "secret data");
String decrypted = pqcEncryption.decryptForSession(session.getSessionId(), encrypted);

// Standalone signing
@Autowired DilithiumSigningEngine dilithium;

KeyPair kp    = dilithium.generateKeyPair();
byte[]  sig   = dilithium.signString(kp.getPrivate(), "payload");
boolean valid = dilithium.verifyString(kp.getPublic(), "payload", sig);

// JWT — injected automatically, exposed via /auth/token + /api/secure
```

### 4. Try it with curl

```bash
# Start the app
mvn spring-boot:run

# ── Handshake + Encryption ────────────────────────────────────────

curl http://localhost:8080/api/pqc/status                          # classical (no headers)
curl -H "X-PQC-Supported: Kyber-768" http://localhost:8080/api/pqc/status   # PQC only
curl -H "X-PQC-Supported: Kyber-768,Dilithium-3" -H "X-PQC-Hybrid: true" \
     http://localhost:8080/api/pqc/status                          # hybrid (max security)

curl -X POST "http://localhost:8080/api/encrypt/e2e?message=HelloPQC"   # full pipeline: handshake + encrypt + decrypt in one call

curl -X POST "http://localhost:8080/api/pqc/sign?message=HelloPQC"          # Dilithium-3
curl -X POST "http://localhost:8080/api/pqc/sign-sphincs?message=HelloPQC"  # SPHINCS+

curl http://localhost:8080/actuator/pqc
curl -X POST http://localhost:8080/actuator/pqc                    # runs benchmark

# ── Dilithium-3 JWT ────────────────────────────────────────────────

TOKEN=$(curl -s -X POST http://localhost:8080/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"secret"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

curl http://localhost:8080/api/secure -H "Authorization: Bearer $TOKEN"
curl http://localhost:8080/api/secure                               # no token → 401

# ── RSA Migration Bridge ────────────────────────────────────────────

curl -X POST "http://localhost:8080/api/migration/bridge-handshake?clientId=my-svc"
curl -X POST "http://localhost:8080/api/migration/simulate-legacy?clientId=billing-svc"
curl -X POST "http://localhost:8080/api/migration/simulate-pqc?clientId=auth-svc"
curl http://localhost:8080/api/migration/status
```

---

## Integrating Into an Existing Spring Boot App

The Quick Start above runs this repo as its own Spring Boot application. When you instead add
`pqc-starter-lib` as a **dependency of your own app**, only some of it comes along automatically —
this section explains exactly what, so there are no surprises.

### What's auto-wired for you (works immediately, any package, zero extra config)

Everything below is registered via Spring Boot's standard auto-configuration mechanism
(`META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`), which works
regardless of your application's base package — no `@ComponentScan` changes needed:

| Bean | Injectable as | Always present? |
|---|---|---|
| `HybridHandshakeOrchestrator` | `@Autowired HybridHandshakeOrchestrator` | Yes (`pqc.enabled=true`, default) |
| `PqcEncryptionService` | `@Autowired PqcEncryptionService` | Yes |
| `AesGcmEngine` | `@Autowired AesGcmEngine` | Yes |
| `DilithiumSigningEngine` / `SphincsSigningEngine` | `@Autowired` | Yes |
| `DilithiumJwtService` / `DilithiumKeyPairHolder` | `@Autowired` | Yes |
| `HybridHandshakeFilter` | registered as a servlet `Filter` — runs on every request | Yes |
| `DilithiumJwtFilter` | registered as a servlet `Filter` | Yes |
| `DilithiumJwtAuthController` | exposes `POST /auth/token`, `GET /api/secure` | Yes |
| `PqcActuatorEndpoint` | exposes `/actuator/pqc` (includes a `keyManagement` block — provider, health, key versions — when Phase 3 is configured) | Yes |
| `QuantumKeyService` + provider | `@Autowired Optional<QuantumKeyService>` | Only if `pqc.key-management.provider` is set |
| `RsaKyberBridgeService` + `RsaMigrationController` | exposes `/api/migration/*` | Yes (`pqc.migration.enabled=true`, default) |
| `AtRestEncryptionService` + `AtRestEncryptionController` | exposes `/api/atrest/*` | Yes (`pqc.atrest.enabled=true`, default) |

**Implication:** simply adding this dependency exposes `/auth/token`, `/api/secure`,
`/api/migration/*`, `/api/atrest/*`, and `/actuator/pqc` on your app, with demo defaults
(`demo-password: secret`). Before deploying:

```yaml
pqc:
  jwt:
    demo-password: ${JWT_DEMO_PASSWORD}   # never leave the "secret" default in production
  migration:
    enabled: false   # disables the whole migration bridge, incl. RsaKyberBridgeService bean
  atrest:
    enabled: false   # disables the whole at-rest module, incl. AtRestEncryptionService bean
```

Note: `enabled: false` for `migration`/`atrest` turns off the entire module — service beans and
REST controller together, since both come from the same `@AutoConfiguration` class (there's no
current option to keep the Java API but drop just the controller). If you need the service but not
the public endpoints, secure `/api/migration/**` / `/api/atrest/**` in your own
`SecurityFilterChain` instead of disabling the property.

### What is NOT auto-wired (demo-only, requires opt-in)

These classes live in the same JAR but rely on classpath **component scanning**, not
auto-configuration — Spring Boot only component-scans downward from your application's own base
package, so they simply won't be found in a host app with a different package:

- `com.pqc.hybrid.config.SecurityConfig` — the `permitAll()` route rules and JWT filter chain wiring shown in this repo's demo
- `com.pqc.hybrid.controller.PqcDemoController` — `/api/pqc/status`, `/api/pqc/sign`, `/api/pqc/sign-sphincs`
- `com.pqc.hybrid.controller.EncryptionDemoController` — `/api/encrypt/*`

If you want them, either copy the class into your own app and adapt it, or explicitly import it:

```java
@Configuration
@Import(com.pqc.hybrid.config.SecurityConfig.class)
public class PqcIntegrationConfig { }
```

For most real integrations you don't want these as-is — you'll write your own `SecurityFilterChain`
covering the auto-exposed routes above, and call `PqcEncryptionService` / signing engines directly
from your own controllers instead of using the demo ones.

### Spring Security note

`spring-boot-starter-security` is a transitive dependency of `pqc-starter-lib`. If your app doesn't
already configure Spring Security, adding this dependency turns on Spring Security's default
behavior — **every** endpoint, including this library's own `/auth/token` (which is meant to be
public), returns `401 Unauthorized` with HTTP Basic challenge behind a random generated password
printed to the console at boot. Verified directly: a fresh app with no security config returns
`401` on `POST /auth/token` the moment this dependency is added. Add your own minimal security
configuration, e.g.:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/auth/**", "/actuator/**").permitAll()
                .requestMatchers("/api/secure/**").authenticated()
                // decide for yourself whether /api/migration/** and /api/atrest/** are
                // internal-only, authenticated, or disabled via the properties above
                .anyRequest().authenticated())
            .httpBasic(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable);
        return http.build();
    }
}
```

---

## Configuration Reference

All properties live under `pqc`. Every value below has a working default — override only
what you need.

| Property | Default | Description |
|---|---|---|
| `pqc.enabled` | `true` | Master switch; `false` disables all PQC (classical only) |
| `pqc.jwt.ttl-minutes` | `60` | JWT lifetime |
| `pqc.jwt.demo-password` | `secret` | Demo login password — **change in production** |
| `pqc.key-management.provider` | *(unset)* | `local` \| `hashicorp-vault` \| `aws-kms` \| `azure-key-vault` \| `gcp-kms`; unset = ephemeral in-memory keys |
| `pqc.key-management.local.key-store-path` | `${user.home}/.pqc-starter-lib/local-master.key` | Local dev master key file |
| `pqc.key-management.local.auto-generate` | `true` | Auto-create the local key store if missing |
| `pqc.key-management.vault.uri` | — | HashiCorp Vault address |
| `pqc.key-management.vault.transit-key-name` | `pqc-starter-lib-master` | Vault Transit key name |
| `pqc.key-management.vault.kv-key-path` | `pqc-starter-lib/keys` | Vault KV v2 path for key metadata |
| `pqc.key-management.rotation.enabled` | `false` | Enable scheduled key rotation |
| `pqc.key-management.rotation.interval-days` | `90` | Rotation interval |
| `pqc.key-management.rotation.deprecation-window-days` | `7` | Grace period before a rotated key is retired |
| `pqc.migration.default-mode` | `BRIDGE` | `RSA_ONLY` \| `BRIDGE` \| `PQC_ONLY` |
| `pqc.migration.rollout-percentage` | `100` | % of `BRIDGE` traffic routed to PQC |
| `pqc.migration.service-overrides.<clientId>` | — | Force a mode for a specific service, ignoring rollout % |
| `pqc.atrest.master-key-hex` | *(blank → random)* | 64 hex chars (32 bytes); random in dev if blank |
| `pqc.atrest.master-key-version` | `1` | Increment after rotation to trigger lazy re-encryption |
| `pqc.atrest.previous-master-key-hex` | *(blank)* | OLD `master-key-hex` value — set during a rotation so already-stored data stays decryptable; remove once fully re-encrypted |
| `pqc.atrest.chunk-size` | `4096` | Streaming file-encryption chunk size (bytes) |

See each subsection's `application.yml` snippet under [Feature Guide](#feature-guide) for full
context, and [`docs/Phase3Implementation.md`](docs/Phase3Implementation.md) for the deepest KMS provider
detail.

---

## Feature Guide

### 1. Hybrid Handshake

PqcStarterLib orchestrates a **hybrid cryptographic handshake** that combines ECDHE-P384 and
Kyber-768 key material, so an attacker must break **both** classical and quantum-safe cryptography
to compromise a session. Supports **runtime mode switching** per client capability with no
reconnection required.

```
Client (legacy)          →  CLASSICAL   (ECDHE-P384 only)
Client (PQC capable)     →  PQC_ONLY    (Kyber-768 only)
Client (hybrid capable)  →  HYBRID      (ECDHE-P384 + Kyber-768 combined)
```

**Hybrid key derivation formula:**

```
SessionKey = HMAC-SHA256(ECDHE_secret || Kyber_secret, session_id)
```

An attacker must break both ECDHE-P384 and Kyber-768 to recover the session key.

---

### 2. AES-256-GCM Data Encryption

The session key derived from the handshake is used directly as an AES-256 key to encrypt payloads:

```
Wire format:
┌─────────────────────────────────────────────────┐
│  IV (12 bytes)  │  Ciphertext + GCM Tag (N+16)  │
└─────────────────────────────────────────────────┘
```

- Fresh random IV per encryption — no IV reuse
- GCM tag authenticates ciphertext — any tampering throws `AEADBadTagException`
- Session ID passed as AAD — ciphertext is bound to its session (replay protection)

```java
HandshakeSession session = pqcEncryption.establishHybridSession("my-client");
String encrypted = pqcEncryption.encryptForSession(session.getSessionId(), payload);
String decrypted = pqcEncryption.decryptForSession(session.getSessionId(), encrypted);
```

---

### 3. Key Management (KMS / Vault)

Persistent, KMS-managed key storage with pluggable provider backends (Strategy pattern):

| Provider | Config value | Use case |
|----------|-------------|----------|
| `LocalDevKeyProvider` | `local` | Dev/test — AES-256-GCM file-based |
| `HashiCorpVaultKeyProvider` | `hashicorp-vault` | Production — Vault Transit + KV v2 |
| `AwsKmsKeyProvider` | `aws-kms` | Production — AWS KMS (stub, ready to extend) |
| `AzureKeyVaultKeyProvider` | `azure-key-vault` | Production — Azure Key Vault (stub) |
| `GcpKmsKeyProvider` | `gcp-kms` | Production — GCP KMS (stub) |

Three managed key IDs, all rotated together by the scheduled `KeyRotationManager` and reflected
live — a rotation takes effect on the very next handshake/token issuance, no restart required:
- `kyber-server-key` — Kyber-768 keypair for handshakes
- `ec-server-key` — ECDHE-P384 keypair for classical handshakes
- `dilithium-signing-key` — Dilithium-3 keypair for JWT signing

Works without any configuration (ephemeral keys). Enable persistent management in
`application.yml`:

```yaml
pqc:
  key-management:
    provider: local
    local:
      key-store-path: ${user.home}/.pqc-starter-lib/local-master.key
      auto-generate: true
```

For AWS/Azure/GCP/Vault setup details, see [`docs/Phase3Implementation.md`](docs/Phase3Implementation.md).

---

### 4. Dilithium-3 Signed JWT

Replaces RS256/ES256 with quantum-safe **Dilithium-3 (FIPS 204)** for JWT signing. Standard
`Authorization: Bearer <token>` flow — drop-in for existing Spring Security setups.

**Token format** (structurally a JWT, `alg: DILITHIUM3`):

```
Base64URL({"alg":"DILITHIUM3","typ":"JWT"})
.Base64URL({"sub":"alice","iat":...,"exp":...,"roles":["USER"]})
.Base64URL(Dilithium-3 signature ~3293 bytes)
```

```bash
# Get a token
curl -X POST http://localhost:8080/auth/token \
     -H "Content-Type: application/json" \
     -d '{"username":"alice","password":"secret"}'

# Use the token
curl http://localhost:8080/api/secure \
     -H "Authorization: Bearer <token>"
```

---

### 5. RSA Migration Bridge

Enables **gradual, service-by-service migration** from RSA-2048 to Kyber-768 / Hybrid PQC without
a hard cut-over. Three migration modes:

| Mode | Behaviour | Quantum-Safe |
|------|-----------|-------------|
| `RSA_ONLY` | Always RSA-2048 OAEP key transport | No |
| `BRIDGE` | PQC preferred, falls back to RSA based on `rollout-percentage` | Partial |
| `PQC_ONLY` | Kyber/Hybrid only — refuses RSA path | Yes |

```
Legacy service   →  RSA_ONLY  →  RSA-2048 OAEP session key
Bridge service   →  BRIDGE    →  PQC (Kyber+ECDHE) if rollout% permits, else RSA
Modern service   →  PQC_ONLY  →  Kyber-768 HYBRID session key
```

Per-service overrides let you pin individual services regardless of global rollout %:

```yaml
pqc:
  migration:
    default-mode: BRIDGE
    rollout-percentage: 75          # 75% of bridge traffic uses PQC
    service-overrides:
      legacy-billing-svc: RSA_ONLY  # this service not migrated yet
      auth-svc: PQC_ONLY            # fully migrated
```

```bash
curl -X POST "http://localhost:8080/api/migration/bridge-handshake?clientId=my-svc"
curl -X POST "http://localhost:8080/api/migration/simulate-legacy?clientId=legacy-svc"
curl -X POST "http://localhost:8080/api/migration/simulate-pqc?clientId=modern-svc"
curl http://localhost:8080/api/migration/status   # live rollout stats
```

---

### 6. Data at Rest (JPA + File Encryption)

Transparent encryption for database fields and files using **HKDF per-record key isolation** and
**chunked AES-256-GCM streaming**. No plaintext ever touches disk or a DB column.

**Field-level encryption** — transparent to JPA via `AttributeConverter`:

```java
@EncryptedField
@Convert(converter = SsnConverter.class)
@Column(length = 512)
private String ssn;   // stored as "v1:<base64>" — decrypted automatically on read
```

Each field gets its own derived key, so a breach of one column key exposes nothing else:

```
recordKey = HKDF-SHA256(masterKey, salt=recordId, info="fieldName:keyVersion")
```

**Streaming file encryption** — chunked PQCS format, bounded memory regardless of file size:

```
┌────────────────────────────────────────────────────────────┐
│  Magic "PQCS" (4B) │ Version (1B) │ ChunkSize (4B)         │
│  [chunk 1]: ChunkLen (4B) │ IV (12B) │ Ciphertext+Tag       │
│  [chunk 2]: ChunkLen (4B) │ IV (12B) │ Ciphertext+Tag       │
│  [EOF: ChunkLen = 0]                                         │
└────────────────────────────────────────────────────────────┘
```

**Key rotation re-encryption** — LAZY (on next read) or EAGER (batch job):

```java
// Lazy: transparently upgrade on every read
String rekeyed = atRestService.reEncryptIfNeeded(stored, recordId, fieldName);

// Check if a value needs migration
boolean stale = atRestService.needsReEncryption(stored);
```

Rotating `master-key-hex` to a genuinely new key requires keeping the OLD key available as
`previous-master-key-hex` until every stored value has been re-encrypted — otherwise data
encrypted under the old key becomes undecryptable the moment the new key replaces it in config:

```yaml
pqc:
  atrest:
    master-key-hex: "2122232425..."           # NEW 32-byte AES key as hex
    master-key-version: 2                     # incremented — triggers lazy re-encryption
    previous-master-key-hex: "0102030405..."  # OLD key — remove once all data is re-encrypted
    chunk-size: 4096
```

Not rotating? Leave `previous-master-key-hex` blank (the default) — decrypt and re-encrypt then
use the same key, as before this property existed.

```bash
# Encrypt a field value
curl -X POST http://localhost:8080/api/atrest/encrypt-field \
  -H "Content-Type: application/json" \
  -d '{"plaintext":"123-45-6789","recordId":"patient-42","fieldName":"ssn"}'

# Decrypt it back
curl -X POST http://localhost:8080/api/atrest/decrypt-field \
  -H "Content-Type: application/json" \
  -d '{"encoded":"v1:AAEC...","recordId":"patient-42","fieldName":"ssn"}'

# Re-encrypt under new key version (lazy)
curl -X POST http://localhost:8080/api/atrest/reencrypt-field \
  -H "Content-Type: application/json" \
  -d '{"encoded":"v1:AAEC...","recordId":"patient-42","fieldName":"ssn"}'

# Encrypt raw bytes (Base64 in/out)
curl -X POST http://localhost:8080/api/atrest/encrypt-bytes \
  -H "Content-Type: application/json" \
  -d '{"keyBase64":"<32-byte-key-b64>","dataBase64":"<file-bytes-b64>"}'

curl http://localhost:8080/api/atrest/status
```

---

## Algorithms Implemented (Real, Not Simulated)

| Engine | Algorithm | NIST Standard | Purpose |
|--------|-----------|--------------|---------|
| `KyberKemEngine` | Kyber-768 | FIPS 203 (ML-KEM) | Key encapsulation — replaces RSA key exchange |
| `DilithiumSigningEngine` | Dilithium-3 | FIPS 204 (ML-DSA) | Digital signatures — JWT signing, message auth |
| `SphincsSigningEngine` | SPHINCS+-SHA2-128f | FIPS 205 (SLH-DSA) | Long-term signing — CA certs, code signing |

All three run on [BouncyCastle](https://www.bouncycastle.org/) 1.78.1+, which implements the
finalized 2024 NIST PQC standards.

---

## Verified Performance

| Mode | Avg Handshake | Quantum-Safe |
|------|--------------|-------------|
| CLASSICAL | sub-millisecond to ~1 ms | No |
| PQC_ONLY | sub-millisecond to ~1 ms | Yes |
| HYBRID | ~1–2 ms | Yes |
| Dilithium-3 sign+verify | ~1–2 ms | Yes |

Measured directly from this repo's test suite on commodity hardware (JDK 17, BouncyCastle
1.78.1) — actual numbers vary by hardware and JIT warm-up state. See
[`docs/Phase1Implementation.md`](docs/Phase1Implementation.md) for the full measured breakdown,
including key and signature sizes.

Measured on commodity hardware via the project's own test suite and `/actuator/pqc` benchmark
endpoint — PQC handshakes are not a meaningful performance regression versus classical ECDHE.

---

## Runtime Switching Protocol

Clients advertise PQC capability via HTTP headers:

| Header | Value | Meaning |
|--------|-------|---------|
| `X-PQC-Supported` | `Kyber-768,Dilithium-3` | Algorithms the client supports |
| `X-PQC-Hybrid` | `true` | Client supports hybrid mode |
| `X-PQC-Version` | `1` | Protocol version |
| `X-PQC-Session` | `<session-id>` | Upgrade existing session |

Server responds with:

| Header | Example | Meaning |
|--------|---------|---------|
| `X-PQC-Mode` | `HYBRID` | Negotiated cipher mode |
| `X-PQC-Session-Id` | `A1B2C3D4...` | Session identifier |
| `X-PQC-Quantum-Safe` | `true` | Whether session is quantum-safe |

---

## Project Structure

```
pqc-starter-lib/
├── pom.xml
├── docs/
│   ├── Architecture.md                      ← System-wide layering, request lifecycle, extension points
│   ├── PlannedPhases.md                     ← Full phase roadmap (1–7)
│   ├── Phase1Implementation.md              ← Core crypto engine (Kyber, Dilithium, SPHINCS+, hybrid KDF)
│   ├── Phase2Implementation.md              ← Spring integration (AES-GCM, filter, auto-config)
│   ├── Phase3Implementation.md              ← KMS architecture + provider guide
│   ├── Phase4ImplementationDetails.md       ← JWT architecture + sequence diagrams
│   ├── Phase5ImplementationDetails.md       ← Migration bridge architecture + scenarios
│   ├── Phase6ImplementationDetails.md       ← Data-at-rest architecture
│   └── AlgoChoicesForJWT.md                 ← Why Dilithium-3 (not Kyber/SPHINCS+)
└── src/
    ├── main/
    │   ├── java/com/pqc/hybrid/
    │   │   ├── PqcStarterLibApplication.java
    │   │   ├── handshake/
    │   │   │   ├── CipherMode.java                   ← CLASSICAL / PQC_ONLY / HYBRID
    │   │   │   ├── ClientCapability.java
    │   │   │   ├── HandshakeSession.java
    │   │   │   ├── KyberKemEngine.java                ← Kyber-768 KEM
    │   │   │   └── HybridHandshakeOrchestrator.java   ← Core switching engine
    │   │   ├── signing/
    │   │   │   ├── DilithiumSigningEngine.java        ← Dilithium-3 sign/verify
    │   │   │   └── SphincsSigningEngine.java          ← SPHINCS+ sign/verify
    │   │   ├── crypto/
    │   │   │   ├── AesGcmEngine.java                  ← AES-256-GCM encrypt/decrypt
    │   │   │   └── PqcEncryptionService.java          ← Handshake + encrypt API
    │   │   ├── jwt/
    │   │   │   ├── DilithiumJwt.java                  ← Parsed token record
    │   │   │   ├── DilithiumJwtException.java         ← EXPIRED / INVALID_SIG / MALFORMED
    │   │   │   ├── DilithiumKeyPairHolder.java        ← KMS or ephemeral keypair
    │   │   │   ├── DilithiumJwtService.java           ← issueToken() + validateToken()
    │   │   │   ├── DilithiumJwtFilter.java            ← Bearer token filter
    │   │   │   └── DilithiumJwtAuthController.java    ← POST /auth/token, GET /api/secure
    │   │   ├── keymanagement/
    │   │   │   ├── api/
    │   │   │   │   ├── KeyManagementProvider.java     ← Strategy interface
    │   │   │   │   ├── KeyVersion.java                ← ACTIVE/DEPRECATED/RETIRED
    │   │   │   │   └── WrappedKeyMaterial.java
    │   │   │   ├── providers/
    │   │   │   │   ├── LocalDevKeyProvider.java       ← AES-256-GCM file-based
    │   │   │   │   ├── HashiCorpVaultKeyProvider.java ← Vault Transit + KV v2
    │   │   │   │   ├── AwsKmsKeyProvider.java         ← stub
    │   │   │   │   ├── AzureKeyVaultKeyProvider.java  ← stub
    │   │   │   │   └── GcpKmsKeyProvider.java         ← stub
    │   │   │   ├── registry/
    │   │   │   │   └── KeyRegistry.java               ← Versioned in-memory key store
    │   │   │   ├── service/
    │   │   │   │   └── QuantumKeyService.java         ← Bootstrap + rotate + provide
    │   │   │   ├── rotation/
    │   │   │   │   └── KeyRotationManager.java        ← Scheduled key rotation
    │   │   │   └── config/
    │   │   │       ├── KeyManagementProperties.java
    │   │   │       └── KeyManagementAutoConfiguration.java
    │   │   ├── migration/
    │   │   │   ├── MigrationMode.java                 ← RSA_ONLY / BRIDGE / PQC_ONLY
    │   │   │   ├── MigrationStats.java                ← Session count snapshot record
    │   │   │   ├── RsaKeyConverter.java               ← RSA-2048 OAEP wrap/unwrap
    │   │   │   ├── RsaKyberBridgeService.java         ← Core bridge: RSA ↔ Kyber
    │   │   │   ├── RsaMigrationController.java        ← /api/migration/* endpoints
    │   │   │   └── config/
    │   │   │       ├── RsaMigrationProperties.java    ← rollout %, per-service overrides
    │   │   │       └── RsaMigrationAutoConfiguration.java
    │   │   ├── atrest/
    │   │   │   ├── annotation/
    │   │   │   │   └── EncryptedField.java            ← marks JPA fields for encryption
    │   │   │   ├── HkdfKeyDerivation.java             ← HKDF-SHA256 per-record key isolation
    │   │   │   ├── EncryptedFieldService.java         ← field encrypt/decrypt, versioned format
    │   │   │   ├── EncryptedAttributeConverter.java   ← abstract JPA AttributeConverter base
    │   │   │   ├── StreamingAesGcmEngine.java         ← chunked PQCS streaming AES-256-GCM
    │   │   │   ├── ReEncryptionService.java           ← lazy/eager re-encryption on key rotation
    │   │   │   ├── AtRestEncryptionService.java       ← top-level API
    │   │   │   ├── AtRestEncryptionController.java    ← /api/atrest/* endpoints
    │   │   │   └── config/
    │   │   │       ├── AtRestEncryptionProperties.java
    │   │   │       └── AtRestEncryptionAutoConfiguration.java
    │   │   ├── filter/
    │   │   │   └── HybridHandshakeFilter.java
    │   │   ├── actuator/
    │   │   │   └── PqcActuatorEndpoint.java           ← /actuator/pqc
    │   │   ├── controller/
    │   │   │   ├── PqcDemoController.java
    │   │   │   └── EncryptionDemoController.java
    │   │   ├── config/
    │   │   │   ├── SecurityConfig.java                ← JWT filter + route rules
    │   │   │   └── PqcProperties.java
    │   │   └── autoconfigure/
    │   │       └── PqcAutoConfiguration.java
    │   └── resources/
    │       ├── application.yml
    │       └── META-INF/spring/
    │           └── org.springframework.boot.autoconfigure.AutoConfiguration.imports
    └── test/
        └── java/com/pqc/hybrid/
            ├── handshake/
            │   └── KyberKemEngineTest.java
            ├── signing/
            │   └── PqcSigningEnginesTest.java
            ├── integration/
            │   └── HybridOrchestratorIntegrationTest.java
            ├── keymanagement/
            │   └── KeyManagementProviderTest.java     ← 15 tests
            ├── jwt/
            │   └── DilithiumJwtTest.java              ← 11 tests
            ├── migration/
            │   └── RsaMigrationBridgeTest.java        ← 10 tests
            └── atrest/
                └── DataAtRestEncryptionTest.java      ← 14 tests
```

---

## Running Tests

```bash
mvn test
```

Expected: **85 tests, 0 failures**.

### Manual Smoke Test

[`test.sh`](test.sh) exercises all six phases end-to-end against a running instance — handshake
mode negotiation, Dilithium/SPHINCS+ signing, the actuator, JWT issuance and validation, the RSA
migration bridge, and data-at-rest field encryption:

```bash
mvn spring-boot:run &   # start the app
bash test.sh             # run the smoke test
```

---

## Roadmap

| Phase | Name | Status |
|-------|------|--------|
| Phase 1 | Core Cryptography Engine | ✅ Done |
| Phase 2 | Spring Boot Integration + Data Encryption | ✅ Done |
| Phase 3 | Key Management (KMS / Vault) | ✅ Done |
| Phase 4 | Spring Security + JWT (Dilithium-3 signed) | ✅ Done |
| Phase 5 | RSA Migration Bridge | ✅ Done |
| Phase 6 | Data at Rest (JPA + File Encryption) | ✅ Done |
| Phase 7 | TLS Layer (PQC-in-TLS 1.3) | 🔮 Future |

See [`docs/PlannedPhases.md`](docs/PlannedPhases.md) for the full roadmap and design rationale.

### Further Reading

| Doc | Covers |
|---|---|
| [`docs/Architecture.md`](docs/Architecture.md) | System-wide layering, request lifecycle, key hierarchies, design patterns, extension points, known gaps |
| [`docs/Phase1Implementation.md`](docs/Phase1Implementation.md) | Core crypto engine — Kyber KEM, Dilithium/SPHINCS+ signing, the hybrid KDF, measured sizes/performance |
| [`docs/Phase2Implementation.md`](docs/Phase2Implementation.md) | Spring Boot integration — AES-GCM engine, `PqcEncryptionService`, handshake filter, auto-configuration |
| [`docs/AlgoChoicesForJWT.md`](docs/AlgoChoicesForJWT.md) | Why Dilithium-3 (not Kyber or SPHINCS+) for JWT signing |
| [`docs/Phase3Implementation.md`](docs/Phase3Implementation.md) | KMS/Vault provider architecture, adding a new provider |
| [`docs/Phase4ImplementationDetails.md`](docs/Phase4ImplementationDetails.md) | JWT architecture and sequence diagrams |
| [`docs/Phase5ImplementationDetails.md`](docs/Phase5ImplementationDetails.md) | Migration bridge architecture and rollout scenarios |
| [`docs/Phase6ImplementationDetails.md`](docs/Phase6ImplementationDetails.md) | Data-at-rest architecture, key isolation, streaming format |

---

## Contributing

Issues and pull requests are welcome. Before opening a PR:

1. Run `mvn test` and confirm all tests pass.
2. Keep changes scoped — one concern per PR.
3. Follow the existing package-by-feature structure (`handshake/`, `crypto/`, `jwt/`,
   `keymanagement/`, `migration/`, `atrest/`) when adding new capability.

For larger changes (new KMS provider, new algorithm, protocol changes), please open an issue
first to discuss the approach.

---

## Security

PqcStarterLib handles cryptographic key material and session data. If you discover a security
vulnerability, please report it privately rather than opening a public issue — contact
**Pankaj Sharma** at PankajSharmaHasSpoken@gmail.com with details and, if possible, a reproduction.

Do not use the demo defaults (`demo-password: secret`, ephemeral/local dev key providers) in
production. See [Configuration Reference](#configuration-reference) for the properties to
override before deploying.

`/api/atrest/encrypt-bytes` and `/api/atrest/decrypt-bytes` accept the AES key directly from the
caller — they're a generic "encrypt/decrypt with any key you supply" utility, not tied to any
server-managed secret. Never expose these two routes with a permissive (`permitAll()`) rule in
production; scope them to trusted/internal callers like you would any raw-crypto utility.

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

```
Copyright 2026 Pankaj Sharma

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
