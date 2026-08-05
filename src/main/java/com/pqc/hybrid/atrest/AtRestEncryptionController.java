package com.pqc.hybrid.atrest;

import com.pqc.hybrid.atrest.config.AtRestEncryptionProperties;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.Map;

/**
 * REST API for Phase 6 Data-at-Rest encryption.
 *
 * Endpoints:
 *   POST /api/atrest/encrypt-field          – encrypt a sensitive field value
 *   POST /api/atrest/decrypt-field          – decrypt a stored field value
 *   POST /api/atrest/reencrypt-field        – force re-encrypt under current key version
 *   POST /api/atrest/encrypt-bytes          – encrypt raw bytes (Base64 in/out)
 *   POST /api/atrest/decrypt-bytes          – decrypt raw bytes (Base64 in/out)
 *   GET  /api/atrest/status                 – key version, chunk size
 *
 * SECURITY WARNING — encrypt-bytes / decrypt-bytes:
 *   Unlike the field endpoints (which use the server-managed master key via HKDF),
 *   these two accept the AES key itself from the caller. They are a generic
 *   "encrypt/decrypt with any key you supply" oracle, not tied to any server
 *   secret. If this controller is reachable (this class ships auto-configured —
 *   see PqcAutoConfiguration/AtRestEncryptionAutoConfiguration and the README's
 *   "Integrating Into an Existing Spring Boot App" section), do not expose these
 *   two routes with a permissive (permitAll) security rule in production; scope
 *   them to trusted/internal callers same as you would any raw-crypto utility.
 */
@RestController
@RequestMapping("/api/atrest")
public class AtRestEncryptionController {

    private final AtRestEncryptionService atRestService;
    private final AtRestEncryptionProperties props;

    public AtRestEncryptionController(AtRestEncryptionService atRestService,
                                       AtRestEncryptionProperties props) {
        this.atRestService = atRestService;
        this.props         = props;
    }

    // ── Field encryption ─────────────────────────────────────────────────────

    /**
     * Encrypt a plaintext field value.
     *
     * Request: { "plaintext": "123-45-6789", "recordId": "patient-42", "fieldName": "ssn" }
     * Response: { "encoded": "v1:AAEC...", "keyVersion": 1 }
     */
    @PostMapping("/encrypt-field")
    public ResponseEntity<Map<String, Object>> encryptField(
            @RequestBody Map<String, String> req) throws Exception {
        String encoded = atRestService.encryptField(
                req.get("plaintext"), req.get("recordId"), req.get("fieldName"));
        return ResponseEntity.ok(Map.of(
                "encoded",    encoded,
                "keyVersion", atRestService.getMasterKeyVersion()));
    }

    /**
     * Decrypt a stored encoded field value.
     *
     * Request: { "encoded": "v1:AAEC...", "recordId": "patient-42", "fieldName": "ssn" }
     * Response: { "plaintext": "123-45-6789" }
     */
    @PostMapping("/decrypt-field")
    public ResponseEntity<Map<String, Object>> decryptField(
            @RequestBody Map<String, String> req) throws Exception {
        String plaintext = atRestService.decryptField(
                req.get("encoded"), req.get("recordId"), req.get("fieldName"));
        return ResponseEntity.ok(Map.of("plaintext", plaintext));
    }

    /**
     * Re-encrypt a field value under the current master key version (if needed).
     *
     * Request: { "encoded": "v1:AAEC...", "recordId": "patient-42", "fieldName": "ssn" }
     * Response: { "encoded": "v2:BBFD...", "rekeyed": true }
     */
    @PostMapping("/reencrypt-field")
    public ResponseEntity<Map<String, Object>> reEncryptField(
            @RequestBody Map<String, String> req) throws Exception {
        String original = req.get("encoded");
        String rekeyed  = atRestService.reEncryptIfNeeded(
                original, req.get("recordId"), req.get("fieldName"));
        return ResponseEntity.ok(Map.of(
                "encoded", rekeyed,
                "rekeyed", !rekeyed.equals(original)));
    }

    // ── Byte-level encryption ─────────────────────────────────────────────────

    /**
     * Encrypt raw bytes (supplied as Base64) using chunked streaming AES-256-GCM.
     * The key must also be supplied as Base64 (32 bytes → 44-char Base64 string).
     *
     * Request: { "keyBase64": "...", "dataBase64": "..." }
     * Response: { "encryptedBase64": "..." }
     *
     * <b>Caller-supplied key — see the class-level SECURITY WARNING.</b> Do not
     * permit unauthenticated/untrusted access to this endpoint in production.
     */
    @PostMapping("/encrypt-bytes")
    public ResponseEntity<Map<String, Object>> encryptBytes(
            @RequestBody Map<String, String> req) throws Exception {
        byte[] key       = Base64.getDecoder().decode(req.get("keyBase64"));
        byte[] data      = Base64.getDecoder().decode(req.get("dataBase64"));
        byte[] encrypted = atRestService.encryptBytes(key, data);
        return ResponseEntity.ok(Map.of(
                "encryptedBase64", Base64.getEncoder().encodeToString(encrypted)));
    }

    /**
     * Decrypt raw bytes (Base64) using chunked streaming AES-256-GCM.
     *
     * Request: { "keyBase64": "...", "encryptedBase64": "..." }
     * Response: { "dataBase64": "..." }
     *
     * <b>Caller-supplied key — see the class-level SECURITY WARNING.</b> Do not
     * permit unauthenticated/untrusted access to this endpoint in production.
     */
    @PostMapping("/decrypt-bytes")
    public ResponseEntity<Map<String, Object>> decryptBytes(
            @RequestBody Map<String, String> req) throws Exception {
        byte[] key       = Base64.getDecoder().decode(req.get("keyBase64"));
        byte[] encrypted = Base64.getDecoder().decode(req.get("encryptedBase64"));
        byte[] data      = atRestService.decryptBytes(key, encrypted);
        return ResponseEntity.ok(Map.of(
                "dataBase64", Base64.getEncoder().encodeToString(data)));
    }

    // ── Status ────────────────────────────────────────────────────────────────

    /**
     * Returns current at-rest encryption configuration metadata.
     */
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> status() {
        return ResponseEntity.ok(Map.of(
                "masterKeyVersion", atRestService.getMasterKeyVersion(),
                "chunkSize",        props.getChunkSize(),
                "keySource",        props.getMasterKeyHex().isBlank() ? "random (dev)" : "config",
                "phase",            "Phase 6 — Data at Rest"));
    }
}
