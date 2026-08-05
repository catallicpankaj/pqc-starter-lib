# Phase 3 — Key Management: Implementation Guide

> Persistent, rotatable, provider-agnostic KMS integration for PqcStarterLib.
> Switch between HashiCorp Vault, AWS KMS, Azure Key Vault, GCP KMS, or local dev
> by changing a single configuration property.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│  HybridHandshakeOrchestrator                                        │
│  (unchanged public API — just receives KMS-managed KeyPairs now)    │
└─────────────────────────┬───────────────────────────────────────────┘
                          │  Optional<QuantumKeyService>
                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│  QuantumKeyService                                                  │
│  ┌──────────────┐  ┌───────────────┐  ┌──────────────────────────┐ │
│  │  bootstrap() │  │  getActive    │  │  rotate(keyId)           │ │
│  │  first start │  │  KyberKeyPair │  │  retireDeprecated(keyId) │ │
│  │  + restart   │  │  EcKeyPair    │  │                          │ │
│  └──────────────┘  └───────────────┘  └──────────────────────────┘ │
└───────────────┬─────────────────────────────────────────────────────┘
                │  KeyManagementProvider (Strategy interface)
       ┌────────┴──────────────────────────────────────────────────┐
       │                                                           │
  ┌────▼──────────────┐  ┌───────────────────┐  ┌───────────────┐ │
  │HashiCorpVault     │  │LocalDevKeyProvider│  │AwsKmsKey      │ │
  │KeyProvider        │  │(file-based AES)   │  │Provider(stub) │ │
  │Transit + KV v2    │  │dev/test only      │  │               │ │
  └───────────────────┘  └───────────────────┘  └───────────────┘ │
       │                                           ┌───────────────┘
  ┌────▼──────────────┐  ┌───────────────────┐
  │AzureKeyVault      │  │GcpKmsKeyProvider  │
  │KeyProvider(stub)  │  │(stub)             │
  └───────────────────┘  └───────────────────┘
```

### Design Patterns Used

| Pattern | Where | Why |
|---|---|---|
| **Strategy** | `KeyManagementProvider` interface | Swap providers with zero code change |
| **Factory (conditional)** | `KeyManagementAutoConfiguration` | Spring selects provider via `@ConditionalOnProperty` |
| **Optional injection** | `HybridHandshakeOrchestrator(Optional<QuantumKeyService>)` | Phase 3 is additive — zero breaking changes to Phase 1/2 |
| **Registry** | `KeyRegistry` | Track all key versions (ACTIVE/DEPRECATED/RETIRED) across restarts |

---

## Package Structure

```
com.pqc.hybrid.keymanagement/
├── api/
│   ├── KeyManagementProvider.java     ← Strategy interface (the only file to implement for a new provider)
│   ├── WrappedKeyMaterial.java        ← Encrypted private key + audit metadata
│   └── KeyVersion.java               ← Versioned key entry (ACTIVE/DEPRECATED/RETIRED lifecycle)
├── providers/
│   ├── HashiCorpVaultKeyProvider.java ← FULL implementation (Transit + KV v2)
│   ├── LocalDevKeyProvider.java       ← FULL implementation (file-based AES-256-GCM, dev only)
│   ├── AwsKmsKeyProvider.java         ← Stub with implementation guide
│   ├── AzureKeyVaultKeyProvider.java  ← Stub with implementation guide
│   └── GcpKmsKeyProvider.java         ← Stub with implementation guide
├── registry/
│   └── KeyRegistry.java              ← In-memory versioned key store (thread-safe)
├── service/
│   └── QuantumKeyService.java        ← Bootstrap, key access, rotation trigger
├── rotation/
│   └── KeyRotationManager.java       ← @Scheduled rotation + retirement
└── config/
    ├── KeyManagementProperties.java  ← pqc.key-management.* config
    └── KeyManagementAutoConfiguration.java ← Spring Boot auto-config wiring
```

---

## Configuration — Switching Providers

**One property controls which provider is active.** All other properties are provider-specific.

### Option A: Local Dev (no external dependencies)

```yaml
pqc:
  key-management:
    provider: local
    local:
      key-store-path: ${user.home}/.pqc-starter-lib/local-master.key
      auto-generate: true   # false = fail if no key file exists
```

- Generates a random AES-256 master key on first startup, saves to `key-store-path`
- Wraps private keys with AES-256-GCM locally
- Stores versioned key data under `~/.pqc-starter-lib/keys/{keyId}/v{n}/`
- **WARNING: NOT for production.** The master key is stored in plaintext on disk.

### Option B: HashiCorp Vault

```yaml
pqc:
  key-management:
    provider: hashicorp-vault
    vault:
      uri: http://localhost:8200
      token: dev-root-token           # or use app-role-id + app-role-secret-id
      transit-key-name: pqc-starter-lib-master
      kv-mount-path: secret
      kv-key-path: pqc-starter-lib/keys
```

**Required Vault setup (one-time):**
```bash
# Enable the Transit secrets engine
vault secrets enable transit

# Create the master key (AES-256-GCM, never exported)
vault write -f transit/keys/pqc-starter-lib-master

# Enable KV v2 (usually pre-enabled in dev server)
vault secrets enable -path=secret kv-v2

# Verify (optional)
vault read transit/keys/pqc-starter-lib-master
```

### Option C: AWS KMS (stub — implement AwsKmsKeyProvider)

```yaml
pqc:
  key-management:
    provider: aws-kms
    aws:
      region: us-east-1
      key-arn: arn:aws:kms:us-east-1:123456789012:key/your-key-id
```

### Option D: Azure Key Vault (stub)

```yaml
pqc:
  key-management:
    provider: azure-key-vault
    azure:
      vault-url: https://my-vault.vault.azure.net
      key-name: pqc-starter-lib-master
      tenant-id: your-tenant-id
      client-id: your-client-id
      client-secret: your-client-secret
```

### Option E: GCP KMS (stub)

```yaml
pqc:
  key-management:
    provider: gcp-kms
    gcp:
      project-id: my-project
      location-id: global
      key-ring-id: pqc-starter-lib
      crypto-key-id: master-key
```

### Phase 3 Disabled (Phase 1/2 behaviour unchanged)

```yaml
pqc:
  enabled: true
  # key-management NOT set → orchestrator uses ephemeral in-memory keys
```

---

## Sequence Diagrams

### Bootstrap — First Startup

```
  Spring Boot           QuantumKeyService       KeyManagementProvider      KeyRegistry
      │                        │                        │                       │
      │  @PostConstruct        │                        │                       │
      │───────────────────────►│                        │                       │
      │                        │  isHealthy()?          │                       │
      │                        │───────────────────────►│                       │
      │                        │◄─── true ──────────────│                       │
      │                        │                        │                       │
      │                        │  listKeyVersions       │                       │
      │                        │  ("kyber-server-key")  │                       │
      │                        │───────────────────────►│                       │
      │                        │◄─── [] (empty) ────────│                       │
      │                        │                        │                       │
      │                        │──┐ BouncyCastle        │                       │
      │                        │  │ generateKeyPair()   │                       │
      │                        │◄─┘ (Kyber-768)         │                       │
      │                        │                        │                       │
      │                        │  wrapKey("kyber-server-key", rawPrivKey)        │
      │                        │───────────────────────►│                       │
      │                        │◄─── WrappedKeyMaterial─│                       │
      │                        │                        │                       │
      │                        │  storeKeyVersion(v1)   │                       │
      │                        │───────────────────────►│ (Vault KV / file)     │
      │                        │                        │                       │
      │                        │  register(v1)          │                       │
      │                        │───────────────────────────────────────────────►│
      │                        │                        │                       │
      │                        │  [repeat for ec-server-key]                    │
      │                        │                        │                       │
      │◄─── bootstrap done ────│                        │                       │
```

### Restart — Loading Existing Keys

```
  Spring Boot           QuantumKeyService       KeyManagementProvider      KeyRegistry
      │                        │                        │                       │
      │  @PostConstruct        │                        │                       │
      │───────────────────────►│                        │                       │
      │                        │  listKeyVersions       │                       │
      │                        │  ("kyber-server-key")  │                       │
      │                        │───────────────────────►│                       │
      │                        │◄─── [1] ───────────────│ (version 1 exists)    │
      │                        │                        │                       │
      │                        │  loadKeyVersion("kyber-server-key", 1)         │
      │                        │───────────────────────►│                       │
      │                        │◄─── KeyVersion(v1) ────│                       │
      │                        │                        │                       │
      │                        │  unwrapKey(wrapped)    │                       │
      │                        │───────────────────────►│                       │
      │                        │◄─── rawPrivKey ────────│ (Vault decrypts)      │
      │                        │                        │                       │
      │                        │──┐ BouncyCastle        │                       │
      │                        │  │ reconstruct KeyPair │                       │
      │                        │◄─┘ from raw bytes      │                       │
      │                        │                        │                       │
      │                        │  register(v1)          │                       │
      │                        │───────────────────────────────────────────────►│
      │◄─── bootstrap done ────│                        │                       │
      │   (same keys as before restart)                                         │
```

### Key Rotation

```
  KeyRotationManager    QuantumKeyService       KeyManagementProvider      KeyRegistry
      │                        │                        │                       │
      │  (cron or manual)      │                        │                       │
      │  rotate("kyber-server-key")                     │                       │
      │───────────────────────►│                        │                       │
      │                        │──┐ BouncyCastle        │                       │
      │                        │  │ new Kyber-768       │                       │
      │                        │◄─┘ generateKeyPair()   │                       │
      │                        │                        │                       │
      │                        │  wrapKey(newPrivKey)   │                       │
      │                        │───────────────────────►│                       │
      │                        │◄─── WrappedKeyMaterial─│                       │
      │                        │                        │                       │
      │                        │  storeKeyVersion(v2, ACTIVE)                   │
      │                        │───────────────────────►│                       │
      │                        │  register(v2)          │                       │
      │                        │───────────────────────────────────────────────►│
      │                        │                        │                       │
      │                        │  v1.deprecate()        │                       │
      │                        │  storeKeyVersion(v1, DEPRECATED)               │
      │                        │───────────────────────►│                       │
      │                        │  register(v1 updated)  │                       │
      │                        │───────────────────────────────────────────────►│
      │                        │                        │                       │
      │                        │  activeKyberKeyPair = newPair (cached)         │
      │◄─── rotation done ─────│                        │                       │
      │                        │                        │                       │
      │  [after deprecation window expires]             │                       │
      │  retireDeprecated("kyber-server-key")           │                       │
      │───────────────────────►│                        │                       │
      │                        │  v1.retire()           │                       │
      │                        │  storeKeyVersion(v1, RETIRED)                  │
      │                        │───────────────────────►│                       │
```

### Per-Request Handshake (Phase 3 active)

```
  HTTP Request    HybridHandshakeFilter   HybridHandshakeOrchestrator   QuantumKeyService
      │                    │                          │                        │
      │  GET /api/...      │                          │                        │
      │───────────────────►│                          │                        │
      │                    │  orchestrate(capability) │                        │
      │                    │─────────────────────────►│                        │
      │                    │                          │  serverKyberKeyPair    │
      │                    │                          │  (already in memory —  │
      │                    │                          │   loaded at bootstrap) │
      │                    │                          │                        │
      │                    │                          │──┐ Kyber encapsulate   │
      │                    │                          │  │ ECDHE key agreement │
      │                    │                          │  │ hybridKdf()         │
      │                    │                          │◄─┘                     │
      │                    │◄── HandshakeSession ─────│                        │
      │◄── X-PQC-Mode: HYBRID                         │                        │
      │    X-PQC-Session-Id: ...                       │                        │
```

---

## Adding a New Provider

To add, say, a **Thales HSM** provider:

**Step 1** — Implement the interface:
```java
public class ThalesHsmKeyProvider implements KeyManagementProvider {

    private final KeyManagementProperties.ThalesHsm config;

    public ThalesHsmKeyProvider(KeyManagementProperties.ThalesHsm config) {
        this.config = config;
    }

    @Override
    public WrappedKeyMaterial wrapKey(String keyId, byte[] rawPrivateKey) throws Exception {
        // Use Thales SDK to wrap using HSM master key
    }

    @Override
    public byte[] unwrapKey(String keyId, WrappedKeyMaterial wrapped) throws Exception {
        // Use Thales SDK to unwrap
    }

    @Override
    public boolean isHealthy() { /* probe HSM connectivity */ }

    @Override
    public String providerName() { return "thales-hsm"; }
}
```

**Step 2** — Add a `@Bean` in `KeyManagementAutoConfiguration`:
```java
@Bean
@ConditionalOnMissingBean(KeyManagementProvider.class)
@ConditionalOnProperty(name = "pqc.key-management.provider", havingValue = "thales-hsm")
KeyManagementProvider thalesHsmKeyProvider(KeyManagementProperties props) {
    return new ThalesHsmKeyProvider(props.getThalesHsm());
}
```

**Step 3** — Add config fields to `KeyManagementProperties`:
```java
public static class ThalesHsm {
    private String host;
    private int    port = 9000;
    private String partitionName;
    // getters/setters...
}
```

**Step 4** — Configure:
```yaml
pqc.key-management.provider: thales-hsm
pqc.key-management.thales-hsm.host: hsm.internal.example.com
pqc.key-management.thales-hsm.partition-name: pqc-starter-lib
```

**No other code changes needed.** `QuantumKeyService`, `HybridHandshakeOrchestrator`,
`KeyRotationManager`, and the actuator endpoint all work with the new provider automatically.

---

## Key Rotation

### Automatic (scheduled)

```yaml
pqc:
  key-management:
    provider: hashicorp-vault
    vault: ...
    rotation:
      enabled: true
      interval-days: 90          # rotate after 90 days
      deprecation-window-days: 7 # keep old key for 7 days before retiring
      cron: "0 0 2 * * *"        # check daily at 2am
```

What happens:
1. `KeyRotationManager` runs the cron daily
2. If any key is older than `interval-days`: calls `QuantumKeyService.rotate(keyId)`
3. New V(N+1) key is generated, wrapped, stored as **ACTIVE**
4. Old V(N) key is updated to **DEPRECATED** in both registry and provider storage
5. After `deprecation-window-days`: old key is updated to **RETIRED**

### Manual (emergency or testing)

```java
// Inject and call directly:
@Autowired KeyRotationManager rotationManager;

rotationManager.triggerRotationNow();              // rotate all keys
rotationManager.triggerRotationNow("kyber-server-key"); // rotate specific key
```

---

## Key Versioning Model

```
ACTIVE     — current key: all new encrypt/wrap operations use this
DEPRECATED — old key: still valid for decrypting existing sessions/records
RETIRED    — no longer used: kept for audit trail only
```

```
Timeline:
  Day 0:  V1 generated → ACTIVE
  Day 90: V2 generated → ACTIVE; V1 → DEPRECATED
          [all existing sessions still decryptable via V1]
  Day 97: V1 → RETIRED (after 7-day deprecation window)
          [only V2 used going forward]
  Day 180: V3 generated → ACTIVE; V2 → DEPRECATED
  ...
```

The registry always keeps DEPRECATED versions available so that data encrypted
with an older key can still be decrypted during the transition window.

---

## What Phase 3 Solves vs Phase 1/2

| Problem | Phase 1/2 | Phase 3 |
|---|---|---|
| Server restart loses keys | Keys regenerated (old ciphertext unreadable) | Keys loaded from KMS (same keys, always) |
| Key rotation | Not possible | Automatic on schedule or on demand |
| Master key in JVM heap | Yes — full exposure in heap dump | No — master key never leaves KMS |
| Compliance (HIPAA/PCI-DSS) | Non-compliant | Compliant (audit log in KMS) |
| Multiple instances share keys | No — each instance has different ephemeral keys | Yes — all instances load same persisted keys |

---

## HashiCorp Vault — Quick Dev Setup

```bash
# Start Vault in dev mode (resets on restart — for dev only)
vault server -dev -dev-root-token-id="dev-root-token"

# In another terminal:
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=dev-root-token

# Enable Transit Secrets Engine
vault secrets enable transit

# Create the pqc-starter-lib master key
vault write -f transit/keys/pqc-starter-lib-master

# Verify
vault read transit/keys/pqc-starter-lib-master
# Should show: type aes256-gcm96, exportable false (key never leaves Vault)

# KV v2 is pre-enabled in dev mode at path "secret"
# Start the app:
mvn spring-boot:run
```

Then configure:
```yaml
pqc.key-management.provider: hashicorp-vault
pqc.key-management.vault.uri: http://localhost:8200
pqc.key-management.vault.token: dev-root-token
```

---

## Running Tests

```bash
# All tests (no Vault required — uses LocalDevKeyProvider)
mvn test

# Phase 3 specific tests only
mvn test -Dtest=KeyManagementProviderTest

# Run with Vault (requires running Vault instance)
export VAULT_URI=http://localhost:8200
export VAULT_TOKEN=dev-root-token
mvn test -Dtest=KeyManagementProviderTest -Dpqc.key-management.provider=hashicorp-vault
```

---

## Actuator Integration

When Phase 3 is active (a `QuantumKeyService` bean exists), `/actuator/pqc` includes a
`keyManagement` block built from `QuantumKeyService.getProviderName()` /
`isProviderHealthy()` and `KeyRegistry.toSummary()`. It is `null` when Phase 3 is not
configured (ephemeral keys).

```bash
curl http://localhost:8080/actuator/pqc
```

Response includes:
```json
{
  "keyManagement": {
    "provider": "hashicorp-vault",
    "providerHealthy": true,
    "keys": {
      "kyber-server-key": [
        { "version": 1, "algorithm": "Kyber-768", "status": "ACTIVE",
          "createdAt": "2026-03-11T...", "keyFingerprint": "ABC123..." }
      ],
      "ec-server-key": [
        { "version": 1, "algorithm": "ECDHE-P384", "status": "ACTIVE",
          "createdAt": "2026-03-11T...", "keyFingerprint": "DEF456..." }
      ]
    }
  }
}
```

For programmatic access (rather than parsing the actuator response), inject `KeyRegistry` or
`QuantumKeyService` directly:

```java
@Autowired KeyRegistry keyRegistry;
@Autowired QuantumKeyService quantumKeyService;

List<KeyVersion> versions = keyRegistry.getAll("kyber-server-key");
String provider = quantumKeyService.getProviderName();
boolean healthy = quantumKeyService.isProviderHealthy();
```
