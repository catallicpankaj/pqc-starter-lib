package com.pqc.hybrid.keymanagement.registry;

import com.pqc.hybrid.keymanagement.api.KeyVersion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * In-memory versioned registry of all managed key pairs.
 *
 * Stores all KeyVersion entries loaded at startup and created during rotation.
 * Thread-safe — uses ConcurrentHashMap internally.
 *
 * STRUCTURE:
 *   keyId → list of KeyVersion entries, sorted by version number (ascending)
 *
 *   e.g. "kyber-server-key" → [V1(DEPRECATED), V2(ACTIVE)]
 *        "ec-server-key"    → [V1(ACTIVE)]
 *
 * BEHAVIOUR:
 *   - getActive(keyId)  → returns the single ACTIVE version (there must always be exactly one)
 *   - getAll(keyId)     → returns all versions (ACTIVE + DEPRECATED + RETIRED)
 *   - getUsableForDecryption(keyId) → ACTIVE + DEPRECATED versions
 *   - findByVersion(keyId, n)       → specific version lookup
 *
 * The registry is populated by QuantumKeyService.bootstrap() at startup and
 * updated by KeyRotationManager during rotation events.
 */
public class KeyRegistry {

    private static final Logger log = LoggerFactory.getLogger(KeyRegistry.class);

    // keyId → sorted list of KeyVersion entries
    private final Map<String, List<KeyVersion>> registry = new ConcurrentHashMap<>();

    // ─────────────────────────────────────────────────────────────
    // Write operations
    // ─────────────────────────────────────────────────────────────

    /**
     * Register a new or updated key version.
     * If a version with the same keyId + version number already exists, it is replaced.
     */
    public synchronized void register(KeyVersion kv) {
        registry.compute(kv.getKeyId(), (id, existing) -> {
            List<KeyVersion> list = existing != null ? new ArrayList<>(existing) : new ArrayList<>();
            list.removeIf(v -> v.getVersion() == kv.getVersion()); // replace if same version
            list.add(kv);
            list.sort(Comparator.comparingInt(KeyVersion::getVersion));
            return list;
        });
        log.debug("[registry] registered: keyId={} version={} status={}",
            kv.getKeyId(), kv.getVersion(), kv.getStatus());
    }

    // ─────────────────────────────────────────────────────────────
    // Read operations
    // ─────────────────────────────────────────────────────────────

    /**
     * Returns the currently ACTIVE version for the given key ID.
     * Throws if no ACTIVE version exists (indicates a configuration error).
     */
    public KeyVersion getActive(String keyId) {
        return getAll(keyId).stream()
            .filter(KeyVersion::isUsableForEncryption)
            .findFirst()
            .orElseThrow(() -> new IllegalStateException(
                "No ACTIVE key version found for keyId=" + keyId +
                ". Ensure QuantumKeyService.bootstrap() completed successfully."));
    }

    /**
     * Returns all versions of the given key (ACTIVE + DEPRECATED + RETIRED),
     * sorted by version number ascending.
     */
    public List<KeyVersion> getAll(String keyId) {
        return Collections.unmodifiableList(
            registry.getOrDefault(keyId, Collections.emptyList()));
    }

    /**
     * Returns all versions usable for decryption (ACTIVE + DEPRECATED).
     * Used when decrypting data that may have been encrypted with an older key.
     */
    public List<KeyVersion> getUsableForDecryption(String keyId) {
        return getAll(keyId).stream()
            .filter(KeyVersion::isUsableForDecryption)
            .collect(Collectors.toList());
    }

    /**
     * Finds a specific version by version number.
     */
    public Optional<KeyVersion> findByVersion(String keyId, int version) {
        return getAll(keyId).stream()
            .filter(v -> v.getVersion() == version)
            .findFirst();
    }

    /**
     * Returns all registered key IDs.
     */
    public Set<String> keyIds() {
        return Collections.unmodifiableSet(registry.keySet());
    }

    /**
     * Returns the highest version number for a key ID, or 0 if none registered.
     */
    public int latestVersion(String keyId) {
        List<KeyVersion> versions = registry.getOrDefault(keyId, Collections.emptyList());
        return versions.isEmpty() ? 0 : versions.get(versions.size() - 1).getVersion();
    }

    /**
     * Summary suitable for actuator / monitoring output.
     */
    public Map<String, Object> toSummary() {
        Map<String, Object> summary = new LinkedHashMap<>();
        for (Map.Entry<String, List<KeyVersion>> entry : registry.entrySet()) {
            List<Map<String, Object>> versions = entry.getValue().stream().map(kv -> {
                Map<String, Object> v = new LinkedHashMap<>();
                v.put("version",         kv.getVersion());
                v.put("algorithm",       kv.getAlgorithm().getLabel());
                v.put("status",          kv.getStatus().name());
                v.put("createdAt",       kv.getCreatedAt().toString());
                v.put("keyFingerprint",  fingerprint(kv));
                if (kv.getDeprecatedAt() != null) v.put("deprecatedAt", kv.getDeprecatedAt().toString());
                return v;
            }).collect(Collectors.toList());
            summary.put(entry.getKey(), versions);
        }
        return summary;
    }

    private String fingerprint(KeyVersion kv) {
        byte[] encoded = kv.getPublicKey().getEncoded();
        return Base64.getEncoder().encodeToString(Arrays.copyOf(encoded, Math.min(8, encoded.length))) + "...";
    }
}
