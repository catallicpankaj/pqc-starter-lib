package com.pqc.hybrid.keymanagement.providers;

import com.pqc.hybrid.keymanagement.api.KeyManagementProvider;
import com.pqc.hybrid.keymanagement.api.KeyVersion;
import com.pqc.hybrid.keymanagement.api.WrappedKeyMaterial;
import com.pqc.hybrid.keymanagement.config.KeyManagementProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Optional;

/**
 * ═══════════════════════════════════════════════════════════════════════
 * GCP KMS KEY PROVIDER — Stub / Extension Point
 * ═══════════════════════════════════════════════════════════════════════
 *
 * STATUS: Stub — ready for implementation.
 *
 * To fully implement GCP Cloud KMS support:
 *
 *   1. Add the GCP KMS dependency to pom.xml:
 *        <dependency>
 *          <groupId>com.google.cloud</groupId>
 *          <artifactId>google-cloud-kms</artifactId>
 *          <version>2.37.0</version>
 *        </dependency>
 *
 *   2. Build the resource name:
 *        String resourceName = CryptoKeyName.of(
 *            config.getProjectId(), config.getLocationId(),
 *            config.getKeyRingId(), config.getCryptoKeyId()).toString();
 *
 *   3. Implement wrapKey() using:
 *        EncryptRequest request = EncryptRequest.newBuilder()
 *            .setName(resourceName)
 *            .setPlaintext(ByteString.copyFrom(rawPrivateKey))
 *            .build();
 *        EncryptResponse response = kmsClient.encrypt(request);
 *        byte[] ciphertext = response.getCiphertext().toByteArray();
 *
 *   4. Implement unwrapKey() using:
 *        DecryptRequest request = DecryptRequest.newBuilder()
 *            .setName(resourceName)
 *            .setCiphertext(ByteString.copyFrom(wrappedBytes))
 *            .build();
 *        DecryptResponse response = kmsClient.decrypt(request);
 *
 *   5. Implement storeKeyVersion() / loadKeyVersion() using GCP Secret Manager:
 *        com.google.cloud:google-cloud-secretmanager
 *
 * ACTIVATE WITH (once implemented):
 *   pqc.key-management.provider=gcp-kms
 *   pqc.key-management.gcp.project-id=my-project
 *   pqc.key-management.gcp.location-id=global
 *   pqc.key-management.gcp.key-ring-id=pqc-starter-lib
 *   pqc.key-management.gcp.crypto-key-id=master-key
 */
public class GcpKmsKeyProvider implements KeyManagementProvider {

    private static final Logger log = LoggerFactory.getLogger(GcpKmsKeyProvider.class);
    private static final String PROVIDER_NAME = "gcp-kms";

    @SuppressWarnings("unused") // will be used once this stub is fully implemented
    private final KeyManagementProperties.GcpKms config;

    public GcpKmsKeyProvider(KeyManagementProperties.GcpKms config) {
        this.config = config;
    }

    @Override
    public WrappedKeyMaterial wrapKey(String keyId, byte[] rawPrivateKey) throws Exception {
        throw new UnsupportedOperationException(
            "GCP KMS provider is a stub — implement wrapKey() with the GCP SDK. " +
            "See class Javadoc for implementation guide.");
    }

    @Override
    public byte[] unwrapKey(String keyId, WrappedKeyMaterial wrapped) throws Exception {
        throw new UnsupportedOperationException("GCP KMS unwrapKey() not yet implemented.");
    }

    @Override
    public void storeKeyVersion(KeyVersion keyVersion) throws Exception {
        throw new UnsupportedOperationException("GCP KMS storeKeyVersion() not yet implemented.");
    }

    @Override
    public Optional<KeyVersion> loadKeyVersion(String keyId, int version) throws Exception {
        throw new UnsupportedOperationException("GCP KMS loadKeyVersion() not yet implemented.");
    }

    @Override
    public List<Integer> listKeyVersions(String keyId) throws Exception {
        throw new UnsupportedOperationException("GCP KMS listKeyVersions() not yet implemented.");
    }

    @Override
    public boolean isHealthy() {
        log.warn("[gcp-kms] isHealthy() is a stub — always returning false until implemented");
        return false;
    }

    @Override
    public String providerName() { return PROVIDER_NAME; }
}
