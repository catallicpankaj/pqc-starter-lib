package com.pqc.hybrid.handshake;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.Security;
import java.util.Arrays;
import java.util.Objects;

/**
 * Real Kyber-768 (ML-KEM) Key Encapsulation Mechanism engine.
 *
 * Uses BouncyCastle BCPQC provider for genuine Kyber-768 operations.
 * This is NOT simulated — actual Kyber encapsulation and decapsulation.
 *
 * Key sizes (Kyber-768):
 *   Public key:  1184 bytes
 *   Private key: 2400 bytes
 *   Ciphertext:  1088 bytes
 *   Shared secret: 32 bytes
 */
@Component
public class KyberKemEngine {

    private static final Logger log = LoggerFactory.getLogger(KyberKemEngine.class);
    private static final String BCPQC = "BCPQC";

    static {
        if (Security.getProvider(BCPQC) == null) {
            Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);
        }
    }

    /**
     * Generate a Kyber-768 key pair (server long-term or ephemeral).
     */
    public KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", BCPQC);
        kpg.initialize(KyberParameterSpec.kyber768);
        return kpg.generateKeyPair();
    }

    /**
     * Encapsulate: given a server's public key, produce:
     *   - a shared secret (stays local at client)
     *   - a ciphertext (sent to server)
     *
     * Both parties derive the same 32-byte shared secret.
     */
    public KemResult encapsulate(PublicKey serverPublicKey) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("Kyber", BCPQC);
        kg.init(new KEMGenerateSpec(serverPublicKey, "AES"));
        SecretKeyWithEncapsulation result = (SecretKeyWithEncapsulation) kg.generateKey();
        byte[] sharedSecret = result.getEncoded();
        byte[] ciphertext   = result.getEncapsulation();
        log.debug("Kyber-768 encapsulation: sharedSecret={} bytes, ciphertext={} bytes",
            sharedSecret.length, ciphertext.length);
        return new KemResult(sharedSecret, ciphertext);
    }

    /**
     * Decapsulate: given the server's private key and client's ciphertext,
     * recover the same shared secret the client derived during encapsulation.
     */
    public byte[] decapsulate(PrivateKey serverPrivateKey, byte[] ciphertext) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("Kyber", BCPQC);
        kg.init(new KEMExtractSpec(serverPrivateKey, ciphertext, "AES"));
        SecretKey recovered = kg.generateKey();
        byte[] sharedSecret = recovered.getEncoded();
        log.debug("Kyber-768 decapsulation: recovered sharedSecret={} bytes", sharedSecret.length);
        return sharedSecret;
    }

    /**
     * Holds both outputs of encapsulation:
     *   sharedSecret — kept locally, fed into hybrid KDF
     *   ciphertext   — sent to server for decapsulation
     */
    public record KemResult(byte[] sharedSecret, byte[] ciphertext) {
        /**
         * Records' auto-generated equals()/hashCode() compare byte[] components by
         * reference, not by content — overridden so two results with the same
         * secret/ciphertext bytes compare equal.
         */
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof KemResult other)) return false;
            return Arrays.equals(sharedSecret, other.sharedSecret)
                && Arrays.equals(ciphertext, other.ciphertext);
        }

        @Override
        public int hashCode() {
            return Objects.hash(Arrays.hashCode(sharedSecret), Arrays.hashCode(ciphertext));
        }
    }
}
