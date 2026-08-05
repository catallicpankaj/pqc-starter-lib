package com.pqc.hybrid.keymanagement.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for Phase 3 Key Management.
 *
 * ROOT PREFIX: pqc.key-management
 *
 * SWITCHING PROVIDERS — just change one property:
 *
 *   spring:
 *     pqc:
 *       key-management:
 *         provider: hashicorp-vault   # or: local | aws-kms | azure-key-vault | gcp-kms
 *
 * When provider is absent or empty, Phase 3 is disabled and the orchestrator
 * uses ephemeral in-memory keys (Phase 1/2 behaviour).
 *
 * FULL EXAMPLE — HashiCorp Vault:
 *
 *   pqc.key-management.provider=hashicorp-vault
 *   pqc.key-management.vault.uri=http://localhost:8200
 *   pqc.key-management.vault.token=dev-root-token
 *   pqc.key-management.vault.transit-key-name=pqc-starter-lib-master
 *   pqc.key-management.vault.kv-mount-path=secret
 *   pqc.key-management.vault.kv-key-path=pqc-starter-lib/keys
 *
 * FULL EXAMPLE — Local (dev only):
 *
 *   pqc.key-management.provider=local
 *   pqc.key-management.local.key-store-path=/home/user/.pqc-starter-lib/local-master.key
 *   pqc.key-management.local.auto-generate=true
 *
 * KEY ROTATION:
 *
 *   pqc.key-management.rotation.enabled=true
 *   pqc.key-management.rotation.interval-days=90
 *   pqc.key-management.rotation.deprecation-window-days=7
 */
@ConfigurationProperties(prefix = "pqc.key-management")
public class KeyManagementProperties {

    /**
     * Active provider name.
     * One of: local | hashicorp-vault | aws-kms | azure-key-vault | gcp-kms
     * Absent = Phase 3 disabled; orchestrator uses ephemeral keys.
     */
    private String provider;

    private Vault    vault    = new Vault();
    private Local    local    = new Local();
    private AwsKms   aws      = new AwsKms();
    private Azure    azure    = new Azure();
    private GcpKms   gcp      = new GcpKms();
    private Rotation rotation = new Rotation();

    // ─────────────────────────────────────────────────────────────
    // HashiCorp Vault
    // ─────────────────────────────────────────────────────────────

    public static class Vault {
        /** Vault server URI. Default: http://localhost:8200 */
        private String uri = "http://localhost:8200";

        /**
         * Vault token for authentication.
         * For production, prefer AppRole auth — set token to null and configure
         * pqc.key-management.vault.app-role.* instead.
         */
        private String token;

        /**
         * Name of the Transit Secrets Engine key used to wrap/unwrap private keys.
         * This key must exist in Vault before the application starts:
         *   vault write -f transit/keys/pqc-starter-lib-master
         */
        private String transitKeyName = "pqc-starter-lib-master";

        /**
         * Mount path of the KV v2 secrets engine where key versions are stored.
         * Default: "secret" (Vault dev server default)
         */
        private String kvMountPath = "secret";

        /**
         * Path within the KV mount where PqcStarterLib stores key metadata.
         * Full Vault path: {kvMountPath}/data/{kvKeyPath}/{keyId}/v{version}
         */
        private String kvKeyPath = "pqc-starter-lib/keys";

        /** AppRole role ID (alternative to token auth) */
        private String appRoleId;

        /** AppRole secret ID (alternative to token auth) */
        private String appRoleSecretId;

        /** Connect timeout in milliseconds */
        private int connectTimeoutMs = 3000;

        /** Read timeout in milliseconds */
        private int readTimeoutMs = 5000;

        public String getUri()                { return uri; }
        public void   setUri(String v)        { uri = v; }
        public String getToken()              { return token; }
        public void   setToken(String v)      { token = v; }
        public String getTransitKeyName()     { return transitKeyName; }
        public void   setTransitKeyName(String v) { transitKeyName = v; }
        public String getKvMountPath()        { return kvMountPath; }
        public void   setKvMountPath(String v){ kvMountPath = v; }
        public String getKvKeyPath()          { return kvKeyPath; }
        public void   setKvKeyPath(String v)  { kvKeyPath = v; }
        public String getAppRoleId()          { return appRoleId; }
        public void   setAppRoleId(String v)  { appRoleId = v; }
        public String getAppRoleSecretId()    { return appRoleSecretId; }
        public void   setAppRoleSecretId(String v) { appRoleSecretId = v; }
        public int    getConnectTimeoutMs()   { return connectTimeoutMs; }
        public void   setConnectTimeoutMs(int v) { connectTimeoutMs = v; }
        public int    getReadTimeoutMs()      { return readTimeoutMs; }
        public void   setReadTimeoutMs(int v) { readTimeoutMs = v; }
    }

    // ─────────────────────────────────────────────────────────────
    // Local (dev / test only)
    // ─────────────────────────────────────────────────────────────

    public static class Local {
        /**
         * File path where the local AES-256 master key is stored (base64 encoded).
         * Created automatically on first startup if auto-generate=true.
         * WARNING: DO NOT use in production. This is for local development only.
         */
        private String keyStorePath = System.getProperty("user.home") + "/.pqc-starter-lib/local-master.key";

        /**
         * If true, generates and saves a random master key on first startup.
         * If false and no key file exists, startup fails with a clear error.
         */
        private boolean autoGenerate = true;

        public String  getKeyStorePath()          { return keyStorePath; }
        public void    setKeyStorePath(String v)  { keyStorePath = v; }
        public boolean isAutoGenerate()           { return autoGenerate; }
        public void    setAutoGenerate(boolean v) { autoGenerate = v; }
    }

    // ─────────────────────────────────────────────────────────────
    // AWS KMS (stub — Phase 5+)
    // ─────────────────────────────────────────────────────────────

    public static class AwsKms {
        /** AWS region where the KMS key is located */
        private String region;

        /** ARN of the KMS Customer Managed Key used for wrapping */
        private String keyArn;

        /** AWS access key ID (prefer IAM instance role in production) */
        private String accessKeyId;

        /** AWS secret access key (prefer IAM instance role in production) */
        private String secretAccessKey;

        public String getRegion()            { return region; }
        public void   setRegion(String v)    { region = v; }
        public String getKeyArn()            { return keyArn; }
        public void   setKeyArn(String v)    { keyArn = v; }
        public String getAccessKeyId()       { return accessKeyId; }
        public void   setAccessKeyId(String v) { accessKeyId = v; }
        public String getSecretAccessKey()   { return secretAccessKey; }
        public void   setSecretAccessKey(String v) { secretAccessKey = v; }
    }

    // ─────────────────────────────────────────────────────────────
    // Azure Key Vault (stub — Phase 5+)
    // ─────────────────────────────────────────────────────────────

    public static class Azure {
        /** Azure Key Vault URI: https://{vault-name}.vault.azure.net */
        private String vaultUrl;

        /** Name of the Key Vault key used for wrapping */
        private String keyName;

        /** Azure AD tenant ID */
        private String tenantId;

        /** Azure AD client (application) ID */
        private String clientId;

        /** Azure AD client secret */
        private String clientSecret;

        public String getVaultUrl()          { return vaultUrl; }
        public void   setVaultUrl(String v)  { vaultUrl = v; }
        public String getKeyName()           { return keyName; }
        public void   setKeyName(String v)   { keyName = v; }
        public String getTenantId()          { return tenantId; }
        public void   setTenantId(String v)  { tenantId = v; }
        public String getClientId()          { return clientId; }
        public void   setClientId(String v)  { clientId = v; }
        public String getClientSecret()      { return clientSecret; }
        public void   setClientSecret(String v) { clientSecret = v; }
    }

    // ─────────────────────────────────────────────────────────────
    // GCP KMS (stub — Phase 5+)
    // ─────────────────────────────────────────────────────────────

    public static class GcpKms {
        /** GCP project ID */
        private String projectId;

        /** KMS location (e.g. "global" or "us-east1") */
        private String locationId;

        /** KMS key ring name */
        private String keyRingId;

        /** KMS crypto key name */
        private String cryptoKeyId;

        /** Path to service account JSON credentials file */
        private String credentialsPath;

        public String getProjectId()         { return projectId; }
        public void   setProjectId(String v) { projectId = v; }
        public String getLocationId()        { return locationId; }
        public void   setLocationId(String v){ locationId = v; }
        public String getKeyRingId()         { return keyRingId; }
        public void   setKeyRingId(String v) { keyRingId = v; }
        public String getCryptoKeyId()       { return cryptoKeyId; }
        public void   setCryptoKeyId(String v){ cryptoKeyId = v; }
        public String getCredentialsPath()   { return credentialsPath; }
        public void   setCredentialsPath(String v) { credentialsPath = v; }
    }

    // ─────────────────────────────────────────────────────────────
    // Key Rotation Policy
    // ─────────────────────────────────────────────────────────────

    public static class Rotation {
        /** Enable automatic scheduled rotation */
        private boolean enabled = false;

        /**
         * Rotation interval in days.
         * After this many days, a new key version is generated and the old
         * version is moved to DEPRECATED status.
         */
        private int intervalDays = 90;

        /**
         * Days to keep deprecated key versions before retiring them.
         * All active sessions must re-negotiate during this window.
         * Should be long enough that no session encrypted with the old key remains.
         */
        private int deprecationWindowDays = 7;

        /** Cron expression for the rotation check scheduler. Default: daily at 2am */
        private String cron = "0 0 2 * * *";

        public boolean isEnabled()               { return enabled; }
        public void    setEnabled(boolean v)     { enabled = v; }
        public int     getIntervalDays()         { return intervalDays; }
        public void    setIntervalDays(int v)    { intervalDays = v; }
        public int     getDeprecationWindowDays(){ return deprecationWindowDays; }
        public void    setDeprecationWindowDays(int v) { deprecationWindowDays = v; }
        public String  getCron()                 { return cron; }
        public void    setCron(String v)         { cron = v; }
    }

    // ─────────────────────────────────────────────────────────────
    // Root-level getters / setters
    // ─────────────────────────────────────────────────────────────

    public String   getProvider()              { return provider; }
    public void     setProvider(String v)      { provider = v; }
    public Vault    getVault()                 { return vault; }
    public void     setVault(Vault v)          { vault = v; }
    public Local    getLocal()                 { return local; }
    public void     setLocal(Local v)          { local = v; }
    public AwsKms   getAws()                   { return aws; }
    public void     setAws(AwsKms v)           { aws = v; }
    public Azure    getAzure()                 { return azure; }
    public void     setAzure(Azure v)          { azure = v; }
    public GcpKms   getGcp()                   { return gcp; }
    public void     setGcp(GcpKms v)           { gcp = v; }
    public Rotation getRotation()              { return rotation; }
    public void     setRotation(Rotation v)    { rotation = v; }
}
