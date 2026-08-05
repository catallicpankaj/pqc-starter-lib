package com.pqc.hybrid.keymanagement.providers;

import com.pqc.hybrid.keymanagement.api.KeyManagementProvider;
import com.pqc.hybrid.keymanagement.api.KeyVersion;
import com.pqc.hybrid.keymanagement.api.WrappedKeyMaterial;
import com.pqc.hybrid.keymanagement.config.KeyManagementProperties;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.*;

/**
 * ═══════════════════════════════════════════════════════════════════════
 * LOCAL DEV KEY PROVIDER
 * File-based AES-256-GCM key wrapping for local development and testing.
 * ═══════════════════════════════════════════════════════════════════════
 *
 * WARNING: DO NOT USE IN PRODUCTION.
 * The master key is stored as a plaintext Base64 file on disk. This is
 * only suitable for local development and CI/testing environments where
 * the convenience of zero-dependency operation outweighs security concerns.
 *
 * WHAT IT DOES:
 *   - On first startup: generates a random AES-256 master key and saves it to
 *     ~/.pqc-starter-lib/local-master.key (Base64 encoded)
 *   - Wraps private keys using AES-256-GCM with the local master key
 *   - Stores versioned key metadata in ~/.pqc-starter-lib/keys/{keyId}/v{n}/
 *   - On restart: loads the same master key → same private keys available
 *
 * ACTIVATE WITH:
 *   pqc.key-management.provider=local
 *
 * STORAGE LAYOUT:
 *   ~/.pqc-starter-lib/
 *   ├── local-master.key          ← AES-256 master key (Base64)
 *   └── keys/
 *       └── {keyId}/
 *           └── v{version}/
 *               ├── wrapped.b64   ← wrapped private key (Base64)
 *               └── meta.properties ← algorithm, status, timestamps, public key
 */
public class LocalDevKeyProvider implements KeyManagementProvider {

    private static final Logger log = LoggerFactory.getLogger(LocalDevKeyProvider.class);

    private static final String ALGORITHM      = "AES/GCM/NoPadding";
    private static final int    IV_BYTES       = 12;
    private static final int    TAG_BITS       = 128;
    private static final int    KEY_BYTES      = 32;
    private static final String PROVIDER_NAME  = "local";

    private final KeyManagementProperties.Local config;
    private final SecureRandom secureRandom = new SecureRandom();
    private byte[] masterKey; // loaded/generated at first use

    static {
        if (Security.getProvider("BC")    == null) Security.insertProviderAt(new BouncyCastleProvider(),    1);
        if (Security.getProvider("BCPQC") == null) Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);
    }

    public LocalDevKeyProvider(KeyManagementProperties.Local config) {
        this.config = config;
    }

    // ─────────────────────────────────────────────────────────────
    // KeyManagementProvider — Wrap / Unwrap
    // ─────────────────────────────────────────────────────────────

    @Override
    public WrappedKeyMaterial wrapKey(String keyId, byte[] rawPrivateKey) throws Exception {
        ensureMasterKeyLoaded();

        byte[] iv = new byte[IV_BYTES];
        secureRandom.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM, "BC");
        cipher.init(Cipher.ENCRYPT_MODE,
            new SecretKeySpec(masterKey, "AES"),
            new GCMParameterSpec(TAG_BITS, iv));
        cipher.updateAAD(keyId.getBytes(StandardCharsets.UTF_8));
        byte[] ciphertext = cipher.doFinal(rawPrivateKey);

        // Wire format: IV (12 bytes) || ciphertext+tag
        byte[] wrapped = new byte[IV_BYTES + ciphertext.length];
        System.arraycopy(iv,         0, wrapped, 0,        IV_BYTES);
        System.arraycopy(ciphertext, 0, wrapped, IV_BYTES, ciphertext.length);

        log.debug("[local] wrapKey: keyId={} plaintext={}B wrapped={}B", keyId, rawPrivateKey.length, wrapped.length);
        return WrappedKeyMaterial.of(keyId, 1, wrapped, ALGORITHM, PROVIDER_NAME, "");
    }

    @Override
    public byte[] unwrapKey(String keyId, WrappedKeyMaterial wrappedMaterial) throws Exception {
        ensureMasterKeyLoaded();

        byte[] wrapped = wrappedMaterial.wrappedBytes();
        byte[] iv = Arrays.copyOfRange(wrapped, 0, IV_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(wrapped, IV_BYTES, wrapped.length);

        Cipher cipher = Cipher.getInstance(ALGORITHM, "BC");
        cipher.init(Cipher.DECRYPT_MODE,
            new SecretKeySpec(masterKey, "AES"),
            new GCMParameterSpec(TAG_BITS, iv));
        cipher.updateAAD(keyId.getBytes(StandardCharsets.UTF_8));
        byte[] plaintext = cipher.doFinal(ciphertext);

        log.debug("[local] unwrapKey: keyId={} recovered={}B", keyId, plaintext.length);
        return plaintext;
    }

    // ─────────────────────────────────────────────────────────────
    // KeyManagementProvider — Persistence
    // ─────────────────────────────────────────────────────────────

    @Override
    public void storeKeyVersion(KeyVersion kv) throws Exception {
        Path dir = versionDir(kv.getKeyId(), kv.getVersion());
        Files.createDirectories(dir);

        // Store wrapped private key
        Files.writeString(dir.resolve("wrapped.b64"),
            Base64.getEncoder().encodeToString(kv.getWrappedPrivateKey().wrappedBytes()));

        // Store metadata as properties
        Properties meta = new Properties();
        meta.setProperty("keyId",        kv.getKeyId());
        meta.setProperty("version",      String.valueOf(kv.getVersion()));
        meta.setProperty("algorithm",    kv.getAlgorithm().name());
        meta.setProperty("status",       kv.getStatus().name());
        meta.setProperty("createdAt",    kv.getCreatedAt().toString());
        meta.setProperty("wrappedAt",    kv.getWrappedPrivateKey().wrappedAt().toString());
        meta.setProperty("publicKey",    Base64.getEncoder().encodeToString(kv.getPublicKey().getEncoded()));
        meta.setProperty("wrapAlgo",     kv.getWrappedPrivateKey().algorithm());
        if (kv.getDeprecatedAt() != null) meta.setProperty("deprecatedAt", kv.getDeprecatedAt().toString());
        if (kv.getRetiredAt()    != null) meta.setProperty("retiredAt",    kv.getRetiredAt().toString());

        try (FileOutputStream fos = new FileOutputStream(dir.resolve("meta.properties").toFile())) {
            meta.store(fos, "PqcStarterLib key version metadata — DO NOT EDIT MANUALLY");
        }
        log.info("[local] stored keyVersion: keyId={} version={} status={}", kv.getKeyId(), kv.getVersion(), kv.getStatus());
    }

    @Override
    public Optional<KeyVersion> loadKeyVersion(String keyId, int version) throws Exception {
        Path dir = versionDir(keyId, version);
        if (!Files.exists(dir.resolve("meta.properties"))) {
            return Optional.empty();
        }

        Properties meta = new Properties();
        try (FileInputStream fis = new FileInputStream(dir.resolve("meta.properties").toFile())) {
            meta.load(fis);
        }

        String wrappedB64 = Files.readString(dir.resolve("wrapped.b64")).trim();
        byte[] wrappedBytes = Base64.getDecoder().decode(wrappedB64);

        WrappedKeyMaterial wrapped = new WrappedKeyMaterial(
            keyId,
            Integer.parseInt(meta.getProperty("version")),
            wrappedBytes,
            meta.getProperty("wrapAlgo"),
            PROVIDER_NAME,
            "",
            Instant.parse(meta.getProperty("wrappedAt"))
        );

        KeyVersion.KeyAlgorithm algo = KeyVersion.KeyAlgorithm.valueOf(meta.getProperty("algorithm"));
        byte[] pubKeyBytes = Base64.getDecoder().decode(meta.getProperty("publicKey"));
        PublicKey publicKey = rebuildPublicKey(algo, pubKeyBytes);

        KeyVersion.Builder builder = KeyVersion.builder()
            .keyId(keyId)
            .version(Integer.parseInt(meta.getProperty("version")))
            .algorithm(algo)
            .publicKey(publicKey)
            .wrappedPrivateKey(wrapped)
            .status(KeyVersion.Status.valueOf(meta.getProperty("status")));

        if (meta.containsKey("deprecatedAt")) builder.deprecatedAt(Instant.parse(meta.getProperty("deprecatedAt")));
        if (meta.containsKey("retiredAt"))    builder.retiredAt(Instant.parse(meta.getProperty("retiredAt")));

        log.info("[local] loaded keyVersion: keyId={} version={}", keyId, version);
        return Optional.of(builder.build());
    }

    @Override
    public List<Integer> listKeyVersions(String keyId) throws Exception {
        Path keyDir = keysRoot().resolve(keyId);
        if (!Files.exists(keyDir)) return List.of();

        List<Integer> versions = new ArrayList<>();
        try (var stream = Files.list(keyDir)) {
            stream.map(p -> p.getFileName().toString())
                  .filter(name -> name.startsWith("v"))
                  .map(name -> { try { return Integer.parseInt(name.substring(1)); } catch (NumberFormatException e) { return -1; } })
                  .filter(v -> v > 0)
                  .sorted()
                  .forEach(versions::add);
        }
        return versions;
    }

    // ─────────────────────────────────────────────────────────────
    // Health check
    // ─────────────────────────────────────────────────────────────

    @Override
    public boolean isHealthy() {
        try {
            ensureMasterKeyLoaded();
            return masterKey != null && masterKey.length == KEY_BYTES;
        } catch (Exception e) {
            log.warn("[local] health check failed: {}", e.getMessage());
            return false;
        }
    }

    @Override
    public String providerName() { return PROVIDER_NAME; }

    // ─────────────────────────────────────────────────────────────
    // Internal helpers
    // ─────────────────────────────────────────────────────────────

    private synchronized void ensureMasterKeyLoaded() throws Exception {
        if (masterKey != null) return;

        File keyFile = new File(config.getKeyStorePath());
        if (keyFile.exists()) {
            String b64 = Files.readString(keyFile.toPath()).trim();
            masterKey = Base64.getDecoder().decode(b64);
            log.info("[local] loaded master key from: {}", keyFile.getAbsolutePath());
        } else if (config.isAutoGenerate()) {
            masterKey = new byte[KEY_BYTES];
            secureRandom.nextBytes(masterKey);
            keyFile.getParentFile().mkdirs();
            Files.writeString(keyFile.toPath(), Base64.getEncoder().encodeToString(masterKey));
            log.warn("[local] generated new master key at: {} — DO NOT USE IN PRODUCTION", keyFile.getAbsolutePath());
        } else {
            throw new IllegalStateException(
                "[local] No master key found at " + config.getKeyStorePath() +
                " and auto-generate=false. Create it or enable auto-generate.");
        }
    }

    private Path keysRoot() {
        return new File(config.getKeyStorePath()).getParentFile().toPath().resolve("keys");
    }

    private Path versionDir(String keyId, int version) {
        return keysRoot().resolve(keyId).resolve("v" + version);
    }

    private PublicKey rebuildPublicKey(KeyVersion.KeyAlgorithm algo, byte[] encoded) throws Exception {
        KeyFactory kf = KeyFactory.getInstance(algo.getBcAlgorithmName(), algo.getBcProviderName());
        return kf.generatePublic(new X509EncodedKeySpec(encoded));
    }
}
