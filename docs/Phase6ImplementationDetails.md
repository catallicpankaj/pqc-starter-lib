# Phase 6 — Data at Rest (JPA + File Encryption)

> Full application-layer tooling for encrypting data before it reaches a database or file system.
> HKDF-SHA256 per-record key isolation, transparent JPA field encryption, chunked streaming
> AES-256-GCM for files of any size, and lazy/eager re-encryption for master key rotation.

---

## Why It Was Needed

Phases 1–5 protect data **in transit** (session encryption, TLS-layer handshake, JWT tokens).
A gap remained for data **at rest**:

| Threat | Without Phase 6 | With Phase 6 |
|--------|----------------|--------------|
| Database backup stolen | All sensitive fields readable | All fields AES-256-GCM encrypted |
| Single field key leaked | Could decrypt everything (one key for all) | Only that field on that record exposed (HKDF per-record) |
| File system accessed | Plaintext files | PQCS-format encrypted blobs |
| Master key rotated | Old ciphertext undecryptable OR all rows re-read by hand | Lazy or batch re-encryption with versioned prefix |

HIPAA, PCI-DSS, and SOC 2 all require application-layer encryption for specific field types
(SSN, credit card numbers, diagnosis codes) — TLS alone does not satisfy these requirements.

---

## What Was Built — Component Summary

```
AtRestEncryptionAutoConfiguration
         │
         ├── HkdfKeyDerivation          ← HKDF-SHA256 per-record key derivation
         │
         ├── EncryptedFieldService      ← field encrypt/decrypt, versioned format
         │       └── uses AesGcmEngine + HkdfKeyDerivation
         │
         ├── ReEncryptionService        ← lazy/eager re-encryption on key rotation
         │       └── uses previousService + currentService (dual-key)
         │
         ├── StreamingAesGcmEngine      ← chunked PQCS file encryption
         │
         └── AtRestEncryptionService    ← top-level API (field + file + re-encryption)
                 └── AtRestEncryptionController  (/api/atrest/*)
```

JPA integration (optional, no Spring dependency required in the core module):

```
EncryptedAttributeConverter (abstract)
         └── extend per field: SsnConverter, DiagnosisConverter, ...
                 └── calls EncryptedFieldService.encryptField / decryptField
```

---

## Key Mechanics

### 1. HKDF-SHA256 Per-Record Key Isolation

```
recordKey = HKDF-SHA256(
    IKM  = masterKey (32 bytes),
    salt = recordId.getBytes(UTF-8),
    info = (fieldName + ":" + keyVersion).getBytes(UTF-8)
)
```

Why this matters:

- **Field isolation**: `patient-42:ssn:1` derives a completely different key from `patient-42:diagnosisCode:1`.
- **Row isolation**: `patient-42:ssn:1` derives a different key from `patient-99:ssn:1`.
- **Version isolation**: `patient-42:ssn:1` derives a different key from `patient-42:ssn:2`.

A single 32-byte master key generates a unique 32-byte AES key for every (record, field, version) triple.

### 2. Versioned Field Format

```
v{keyVersion}:{Base64(IV || Ciphertext+GCM-Tag)}
```

Example:
```
v1:AAECBAUGB...   ← IV (12B) + Ciphertext + GCM tag (16B), all Base64-encoded
v2:BBFDC...       ← same content, re-encrypted under version-2 master key
```

The version prefix lets decryption parse which master key version to use without any external metadata.

### 3. AAD for Context Binding

Each field encryption uses AAD (Additional Authenticated Data):

```
AAD = "recordId:fieldName:keyVersion"
```

This binds the ciphertext to its context. Moving a ciphertext from one row or field to another will fail GCM authentication. A database injection that swaps encrypted columns is detected.

### 4. Chunked PQCS Streaming Format

Wire format for stream/file encryption:

```
┌──────────────────────────────────────────────────────────────────┐
│  Magic "PQCS" (4B)  │  Version 0x01 (1B)  │  ChunkSize (4B)     │
├──────────────────────────────────────────────────────────────────┤
│  Chunk 1: ChunkLen (4B) │ IV (12B) │ Ciphertext+GCM-Tag          │
│  Chunk 2: ChunkLen (4B) │ IV (12B) │ Ciphertext+GCM-Tag          │
│  ...                                                              │
│  EOF marker: ChunkLen = 0 (4B of zeroes)                         │
└──────────────────────────────────────────────────────────────────┘
```

Each chunk:
- Gets a fresh random 12-byte IV (no IV reuse across chunks)
- Has its own GCM tag — tampering in any single chunk is immediately detected
- Includes its index as AAD → prevents chunk reordering attacks

Default chunk: **4096 bytes** (configurable). Memory usage is bounded by chunk size regardless of file size.

### 5. Key Rotation — Versioned Re-Encryption

When the master key is rotated (V1 → V2):
1. Update `masterKeyHex` in config and increment `masterKeyVersion` to 2
2. Existing V1 values in the DB have the prefix `v1:` — still decryptable with V1 key
3. On next read, call `reEncryptIfNeeded(encoded, recordId, fieldName)` → returns `v2:...`
4. Write `v2:...` back to the DB
5. Repeat until no `v1:` rows remain

The `ReEncryptionService` dual-key constructor makes this explicit:

```java
ReEncryptionService reEnc = new ReEncryptionService(
    previousService,   // old master key — used for DECRYPTION of v1 values
    currentService     // new master key — used for RE-ENCRYPTION to v2
);
```

---

## Sequence Diagrams

### Field Encryption (JPA INSERT)

```
JPA                EncryptedAttributeConverter        EncryptedFieldService
 │                         │                                  │
 │  convertToDatabaseColumn("123-45-6789")                    │
 │ ─────────────────────→  │                                  │
 │                         │  encryptField(pt, recId, field)  │
 │                         │ ───────────────────────────────→ │
 │                         │                                  │ HKDF(masterKey, recId, fieldName:version)
 │                         │                                  │ ──── derivedKey (32B) ────
 │                         │                                  │ AES-256-GCM encrypt(pt, aad)
 │                         │                                  │ ──── "v1:<base64>" ────
 │                         │  "v1:<base64>"                   │
 │                         │ ←─────────────────────────────── │
 │  "v1:<base64>" written to DB
 │ ←─────────────────────  │
```

### Field Decryption (JPA SELECT)

```
JPA                EncryptedAttributeConverter        EncryptedFieldService
 │                         │                                  │
 │  convertToEntityAttribute("v1:<base64>")                   │
 │ ─────────────────────→  │                                  │
 │                         │  decryptField(enc, recId, field) │
 │                         │ ───────────────────────────────→ │
 │                         │                                  │ parse version=1 from "v1:"
 │                         │                                  │ HKDF(masterKey, recId, fieldName:1)
 │                         │                                  │ AES-256-GCM decrypt(ct, aad)
 │                         │                                  │ ──── "123-45-6789" ────
 │                         │  "123-45-6789"                   │
 │                         │ ←─────────────────────────────── │
 │  "123-45-6789" returned to application
 │ ←─────────────────────  │
```

### Lazy Re-Encryption on Read (Key Rotation)

```
Application        ReEncryptionService       prevService (V1)    currService (V2)
     │                     │                       │                    │
     │  reEncryptIfNeeded(  │                       │                    │
     │    "v1:...",         │                       │                    │
     │    recId, field)     │                       │                    │
     │ ──────────────────→  │                       │                    │
     │                      │ needsReEncryption?     │                    │
     │                      │ (version=1 < curr=2 → true)               │
     │                      │                       │                    │
     │                      │ decryptField(v1:..., recId, field, v=1)   │
     │                      │ ─────────────────────→ │                  │
     │                      │ "plaintext"            │                  │
     │                      │ ←───────────────────── │                  │
     │                      │                                           │
     │                      │ encryptField("plaintext", recId, field, v=2)
     │                      │ ─────────────────────────────────────────→│
     │                      │ "v2:..."                                   │
     │                      │ ←─────────────────────────────────────────│
     │  "v2:..."            │
     │ ←─────────────────── │
     │ (caller writes "v2:..." back to DB)
```

### File Encryption

```
Caller                     AtRestEncryptionService       StreamingAesGcmEngine
  │                                │                             │
  │  encryptFile(key, inStream,    │                             │
  │              outStream)        │                             │
  │ ────────────────────────────→  │                             │
  │                                │  encryptStream(key, in, out)│
  │                                │ ───────────────────────────→│
  │                                │                             │ write header [PQCS|v1|4096]
  │                                │                             │ loop:
  │                                │                             │   read 4096B from inStream
  │                                │                             │   randomIV = SecureRandom(12B)
  │                                │                             │   ct = AES-GCM(key, iv, chunk, AAD=index)
  │                                │                             │   write [chunkLen|iv|ct]
  │                                │                             │ write [chunkLen=0]
  │ ← outStream filled with PQCS blob ────────────────────────────│
```

---

## Component Reference

### `HkdfKeyDerivation`

```java
// Derive a 32-byte AES key for a specific (record, field, version) triple
byte[] key = hkdf.deriveFieldKey(masterKey, "patient-42", "ssn", 1);

// Composite primary key — joined with "|"
byte[] key = hkdf.deriveFieldKey(masterKey, new String[]{"tenantA", "order-7"}, "total", 1);
```

### `EncryptedFieldService`

```java
// Encrypt (uses current masterKeyVersion)
String encoded = svc.encryptField("secret", "rec-1", "col");
// → "v1:<base64>"

// Decrypt (auto-parses version from prefix)
String plain = svc.decryptField("v1:<base64>", "rec-1", "col");

// Check if re-encryption needed
boolean stale = svc.needsReEncryption("v1:<base64>");  // true if version < masterKeyVersion
```

### `EncryptedAttributeConverter` — JPA Usage

```java
@Converter
public class SsnConverter extends EncryptedAttributeConverter {
    @Autowired EncryptedFieldService service;

    @Override protected EncryptedFieldService getService() { return service; }
    @Override protected String getFieldName()              { return "ssn"; }
    @Override protected String getRecordId()               {
        return "ssn"; // table-level isolation (default)
        // or override to use entity.getId().toString() for row-level isolation
    }
}

@Entity
public class PatientRecord {
    @Id private Long id;

    @EncryptedField(sensitivity = "PHI")
    @Convert(converter = SsnConverter.class)
    @Column(length = 512)   // encrypted value is ~100 chars for short plaintext
    private String ssn;
}
```

### `StreamingAesGcmEngine` — Direct File API

```java
StreamingAesGcmEngine engine = new StreamingAesGcmEngine();  // 4096-byte chunks

// Encrypt a file
try (InputStream in  = new FileInputStream("report.pdf");
     OutputStream out = new FileOutputStream("report.enc")) {
    engine.encryptStream(fileKey, in, out);
}

// Decrypt
try (InputStream in  = new FileInputStream("report.enc");
     OutputStream out = new FileOutputStream("report.pdf.dec")) {
    engine.decryptStream(fileKey, in, out);
}
```

### `ReEncryptionService` — Key Rotation

```java
// Single-key (no rotation in progress — both keys are the same)
ReEncryptionService reEnc = new ReEncryptionService(fieldService);

// Dual-key (active rotation: V1 → V2)
ReEncryptionService reEnc = new ReEncryptionService(
    fieldServiceV1,  // previous — for decrypting old values
    fieldServiceV2   // current  — for re-encrypting to new version
);

// Lazy re-encryption on read
String updated = reEnc.reEncryptIfNeeded(stored, recordId, fieldName);
// Returns "v2:..." if stored was "v1:..." (and writes nothing — caller must persist)
// Returns original unchanged if already at current version

// Check without migrating
boolean stale = reEnc.needsReEncryption(stored);
```

### `AtRestEncryptionService` — Top-Level API

```java
@Autowired AtRestEncryptionService atRest;

// Field-level
String enc = atRest.encryptField("123-45-6789", "patient-42", "ssn");
String pt  = atRest.decryptField(enc, "patient-42", "ssn");

// File encryption
atRest.encryptFile(fileKey, inputStream, outputStream);
atRest.decryptFile(fileKey, inputStream, outputStream);

// Byte array convenience
byte[] encrypted = atRest.encryptBytes(fileKey, data);
byte[] decrypted = atRest.decryptBytes(fileKey, encrypted);

// Key rotation
String rekeyed    = atRest.reEncryptIfNeeded(enc, "patient-42", "ssn");
boolean needsRek  = atRest.needsReEncryption(enc);
int version       = atRest.getMasterKeyVersion();
```

---

## REST API Reference

Base URL: `http://localhost:8080/api/atrest`

### `POST /encrypt-field`

Encrypt a plaintext string for database storage.

```bash
curl -X POST http://localhost:8080/api/atrest/encrypt-field \
  -H "Content-Type: application/json" \
  -d '{"plaintext":"123-45-6789","recordId":"patient-42","fieldName":"ssn"}'
```

Response:
```json
{
  "encoded": "v1:AAECBAUGB...",
  "keyVersion": 1
}
```

### `POST /decrypt-field`

Decrypt a stored value back to plaintext.

```bash
curl -X POST http://localhost:8080/api/atrest/decrypt-field \
  -H "Content-Type: application/json" \
  -d '{"encoded":"v1:AAECBAUGB...","recordId":"patient-42","fieldName":"ssn"}'
```

Response:
```json
{ "plaintext": "123-45-6789" }
```

### `POST /reencrypt-field`

Re-encrypt a stored value under the current master key version.

```bash
curl -X POST http://localhost:8080/api/atrest/reencrypt-field \
  -H "Content-Type: application/json" \
  -d '{"encoded":"v1:AAEC...","recordId":"patient-42","fieldName":"ssn"}'
```

Response:
```json
{
  "encoded": "v2:BBFDC...",
  "rekeyed": true
}
```
`rekeyed: false` means the value was already at the current version (no-op).

### `POST /encrypt-bytes`

Encrypt raw bytes using streaming AES-256-GCM (PQCS format).

```bash
# Generate a 32-byte key and encode to Base64
KEY=$(openssl rand -base64 32)

# Encrypt
curl -X POST http://localhost:8080/api/atrest/encrypt-bytes \
  -H "Content-Type: application/json" \
  -d "{\"keyBase64\":\"$KEY\",\"dataBase64\":\"$(echo -n 'hello world' | base64)\"}"
```

Response:
```json
{ "encryptedBase64": "UFFD..." }
```

### `POST /decrypt-bytes`

Decrypt raw bytes produced by `/encrypt-bytes`.

```bash
curl -X POST http://localhost:8080/api/atrest/decrypt-bytes \
  -H "Content-Type: application/json" \
  -d "{\"keyBase64\":\"$KEY\",\"encryptedBase64\":\"UFFD...\"}"
```

Response:
```json
{ "dataBase64": "aGVsbG8gd29ybGQ=" }
```

### `GET /status`

Returns current at-rest encryption metadata.

```bash
curl http://localhost:8080/api/atrest/status
```

Response:
```json
{
  "masterKeyVersion": 1,
  "chunkSize": 4096,
  "keySource": "config",
  "phase": "Phase 6 — Data at Rest"
}
```

---

## Configuration Reference

```yaml
pqc:
  atrest:
    enabled: true                  # default: true; set false to disable all at-rest beans
    master-key-hex: ""             # 64 hex chars (32 bytes)
                                   # leave blank: ephemeral random key generated (dev only)
    master-key-version: 1          # increment after rotating masterKeyHex
    chunk-size: 4096               # streaming chunk size in bytes (default: 4096)
```

**Master key generation for production:**

```bash
# Generate a secure 32-byte key (64 hex chars)
openssl rand -hex 32
# → e.g. 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
```

Store the key in Vault, AWS Secrets Manager, or Kubernetes secrets — never hard-code in `application.yml` in production.

---

## Example Scenarios

### Scenario A: Day 0 — Enable At-Rest Encryption

```yaml
pqc:
  atrest:
    master-key-hex: "0102...1f20"    # 32-byte key from Vault
    master-key-version: 1
```

New records stored with `v1:` prefix. All fields encrypted transparently via JPA converters.

---

### Scenario B: Master Key Rotation

```
Day 0:   master-key-hex = "abc...", master-key-version = 1
Day 90:  Generate new key → "def..."
         Deploy: master-key-hex = "def...", master-key-version = 2
         All new writes → "v2:..."
         Existing rows → still "v1:..." (decryptable with V1 key)
Day 91+: Lazy re-encryption: each read checks needsReEncryption → rewrites "v2:..."
         OR batch job: iterate all records → reEncryptField for each
Day 120: No more "v1:" rows in DB → decommission V1 key
```

Auto-config for rotation window (both V1 and V2 services active):

```java
// In a custom @Configuration during rotation window:
@Bean
ReEncryptionService reEncryptionService(AtRestEncryptionProperties props) {
    EncryptedFieldService v1Svc = new EncryptedFieldService(aesGcm, hkdf, keyV1, 1);
    EncryptedFieldService v2Svc = new EncryptedFieldService(aesGcm, hkdf, keyV2, 2);
    return new ReEncryptionService(v1Svc, v2Svc);
}
```

---

### Scenario C: JPA Entity Full Setup

```java
// 1. Define converters (one per encrypted field)
@Converter
public class SsnConverter extends EncryptedAttributeConverter {
    @Autowired EncryptedFieldService service;
    @Override protected EncryptedFieldService getService() { return service; }
    @Override protected String getFieldName()              { return "ssn"; }
}

@Converter
public class DiagnosisConverter extends EncryptedAttributeConverter {
    @Autowired EncryptedFieldService service;
    @Override protected EncryptedFieldService getService() { return service; }
    @Override protected String getFieldName()              { return "diagnosisCode"; }
}

// 2. Annotate the entity
@Entity
public class PatientRecord {
    @Id @GeneratedValue
    private Long id;

    @EncryptedField(sensitivity = "PHI")
    @Convert(converter = SsnConverter.class)
    @Column(length = 512)
    private String ssn;

    @EncryptedField(sensitivity = "PHI")
    @Convert(converter = DiagnosisConverter.class)
    @Column(length = 512)
    private String diagnosisCode;
}

// 3. Use normally — encryption/decryption is transparent
PatientRecord p = new PatientRecord();
p.setSsn("123-45-6789");          // JPA calls SsnConverter.convertToDatabaseColumn
p.setDiagnosisCode("Z00.00");
repo.save(p);                     // DB stores "v1:AAEC..." in ssn column

PatientRecord loaded = repo.findById(p.getId()).get();
loaded.getSsn();                  // "123-45-6789" — decrypted by JPA on SELECT
```

---

### Scenario D: Large File Encryption

```java
@Autowired AtRestEncryptionService atRest;

// Derive a file key (or use a stored key — Phase 3 KMS)
byte[] fileKey = new byte[32];
new SecureRandom().nextBytes(fileKey);

// Encrypt a file to S3-compatible stream
try (InputStream in  = s3Client.getObject("bucket", "report.pdf");
     OutputStream out = s3Client.putObject("bucket", "report.enc")) {
    atRest.encryptFile(fileKey, in, out);
}

// Decrypt on download
try (InputStream in  = s3Client.getObject("bucket", "report.enc");
     OutputStream out = response.getOutputStream()) {
    atRest.decryptFile(fileKey, in, out);
}
```

Memory usage: bounded by 4096-byte chunk size regardless of file size.

---

## Test Coverage

| Test | What it verifies |
|------|-----------------|
| `hkdfDerivesSizedKey` | HKDF outputs a 32-byte key |
| `hkdfFieldIsolation` | Different field names → different derived keys |
| `hkdfRowIsolation` | Different recordIds → different derived keys |
| `fieldEncryptDecryptRoundTrip` | Encrypt + decrypt returns original, prefix = "v1:" |
| `fieldEncryptionIsRandomised` | Same plaintext → different ciphertext (fresh IV each time) |
| `needsReEncryptionDetectsOldVersion` | v1 value flagged by v2 service; not flagged by v1 service |
| `streamingRoundTripSmall` | Small payload: encrypt + decrypt + verify exact bytes |
| `streamingRoundTripMultiChunk` | 200 bytes in 32-byte chunks → correct multi-chunk round-trip |
| `streamingWrongKeyFails` | Wrong key causes GCM authentication failure |
| `reEncryptIfNeededMigratesValue` | v1 → v2 re-encryption, plaintext preserved |
| `reEncryptIfNeededSkipsCurrentVersion` | Calling twice is idempotent |
| `atRestBytesRoundTrip` | `AtRestEncryptionService.encryptBytes / decryptBytes` |
| `autoConfigurationSupportsMasterKeyRotation` | `previous-master-key-hex` lets a genuine master key rotation re-encrypt old data instead of stranding it |
| `autoConfigurationSingleKeyWhenNoPreviousKeyConfigured` | Single-key behaviour is unchanged when no rotation is in progress |

Total: **14 tests, 0 failures** (part of the 85-test suite).

---

## Design Decisions

### Why HKDF and not just AES-KW or a random per-field key?

HKDF allows **stateless key derivation**. You never need to store per-field keys anywhere — the derived key can always be re-derived from the master key + context. This means:
- No key storage explosion (1 master key → unlimited derived keys)
- No key distribution problem (each service re-derives, not fetches)
- Revocation by rotating the master key invalidates all derived keys

### Why an abstract converter instead of a single universal one?

A single converter cannot provide per-field HKDF key isolation because it has no way to know the field name or record ID at conversion time without extra wiring. The abstract pattern makes the design contract explicit: subclasses provide the context needed for HKDF.

### Why include chunk index in AAD for streaming?

Without the chunk index in AAD, an attacker could reorder chunks in a PQCS file — each chunk would pass GCM verification individually, but the reassembled plaintext would be corrupted. Including the index binds each chunk to its expected position.

### Why two separate services in `ReEncryptionService`?

The alternative (one service knowing both keys) requires the service to hold key material for multiple key versions. The dual-service constructor is explicit about the security boundary: the previous key is used exactly once (for decryption of old values) and then goes out of scope. This prevents accidental re-use of an old key for new encryptions.

### Why `v{n}:` prefix instead of a separate metadata column?

Self-describing ciphertext eliminates the need for a separate schema migration when key versions change. A `v1:` prefix in an existing VARCHAR column is backwards-compatible with any schema. No foreign key to a "key versions" table, no JOIN required.
