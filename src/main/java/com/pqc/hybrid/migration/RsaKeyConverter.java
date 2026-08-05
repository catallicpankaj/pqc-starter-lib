package com.pqc.hybrid.migration;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.security.*;

/**
 * RSA-2048 OAEP key wrapping utility for the Migration Bridge.
 *
 * Implements RSA-OAEP (with SHA-256) key transport — the pattern used in
 * TLS 1.2 RSA cipher suites. Allows the bridge to speak RSA to legacy
 * services while internally producing the same session-key format as
 * the Kyber path, so both paths yield interchangeable HandshakeSessions.
 *
 * Key exchange protocol:
 *   1. Client generates 32 random bytes (session key material).
 *   2. Client encrypts them with the server's RSA public key → wrapped bytes.
 *   3. Client sends wrapped bytes to server.
 *   4. Server decrypts with RSA private key → recovers session key material.
 *   Both sides now share the same 32-byte session key — same as Kyber path.
 *
 * In the bridge demo the server performs both sides to prove the round-trip.
 */
public class RsaKeyConverter {

    private static final Logger log = LoggerFactory.getLogger(RsaKeyConverter.class);
    private static final String RSA_ALGORITHM = "RSA/ECB/OAEPWithSHA256AndMGF1Padding";
    private static final int    RSA_KEY_BITS  = 2048;
    private static final String BC            = "BC";

    private final KeyPair serverRsaKeyPair;

    public RsaKeyConverter() throws Exception {
        if (Security.getProvider(BC) == null)
            Security.insertProviderAt(new BouncyCastleProvider(), 1);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BC);
        kpg.initialize(RSA_KEY_BITS, new SecureRandom());
        this.serverRsaKeyPair = kpg.generateKeyPair();

        log.info("RsaKeyConverter: RSA-{} key pair ready ({} bytes encoded public key)",
                RSA_KEY_BITS, serverRsaKeyPair.getPublic().getEncoded().length);
    }

    /**
     * Wrap (encrypt) key material using the server's RSA public key.
     * Simulates the client side of RSA key transport.
     *
     * @param keyMaterial  32-byte session key material to wrap
     * @return             RSA-OAEP encrypted bytes (~256 bytes for RSA-2048)
     */
    public byte[] wrapKeyMaterial(byte[] keyMaterial) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM, BC);
        cipher.init(Cipher.ENCRYPT_MODE, serverRsaKeyPair.getPublic());
        return cipher.doFinal(keyMaterial);
    }

    /**
     * Unwrap (decrypt) key material using the server's RSA private key.
     * Simulates the server side of RSA key transport.
     *
     * @param wrapped  RSA-OAEP encrypted bytes from wrapKeyMaterial()
     * @return         recovered 32-byte session key material
     */
    public byte[] unwrapKeyMaterial(byte[] wrapped) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM, BC);
        cipher.init(Cipher.DECRYPT_MODE, serverRsaKeyPair.getPrivate());
        return cipher.doFinal(wrapped);
    }

    public PublicKey  getServerPublicKey()  { return serverRsaKeyPair.getPublic(); }
    public PrivateKey getServerPrivateKey() { return serverRsaKeyPair.getPrivate(); }
    public int        getKeyBits()          { return RSA_KEY_BITS; }
}
