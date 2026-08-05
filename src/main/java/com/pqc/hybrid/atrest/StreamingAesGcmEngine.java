package com.pqc.hybrid.atrest;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Chunked streaming AES-256-GCM encryption for large files.
 *
 * Unlike {@link com.pqc.hybrid.crypto.AesGcmEngine} which loads the entire
 * payload into memory, this engine processes data in fixed-size chunks.
 * Each chunk is independently encrypted with its own IV and GCM tag, so:
 *   - Files of arbitrary size can be encrypted with bounded memory usage.
 *   - Any tampered chunk is detected immediately on decryption.
 *   - Partial reads are possible — decrypt only the chunks you need.
 *
 * Wire format (written to OutputStream):
 * ┌──────────────────────────────────────────────────────────────────┐
 * │  Magic (4B)  │  Version (1B)  │  ChunkSize (4B)                 │
 * │  [chunk 1]:  │  ChunkLen (4B) │  IV (12B) │  Ciphertext+Tag     │
 * │  [chunk 2]:  │  ChunkLen (4B) │  IV (12B) │  Ciphertext+Tag     │
 * │  ...                                                             │
 * │  [EOF marker: ChunkLen = 0]                                      │
 * └──────────────────────────────────────────────────────────────────┘
 *
 * - Magic:       0x50 0x51 0x43 0x53 ("PQCS" — PqcStarterLib Chunked Stream)
 * - Version:     0x01
 * - ChunkSize:   plaintext bytes per chunk (4096 by default)
 * - ChunkLen:    total bytes in this chunk entry (IV + Ciphertext + GCM Tag)
 * - GCM Tag:     16 bytes, automatically appended by AES/GCM/NoPadding
 *
 * Each chunk uses a fresh random 12-byte IV. The chunk index is included
 * in AAD to prevent chunk reordering attacks.
 */
public class StreamingAesGcmEngine {

    private static final Logger log = LoggerFactory.getLogger(StreamingAesGcmEngine.class);

    static final byte[] MAGIC        = { 0x50, 0x51, 0x43, 0x53 }; // "PQCS"
    static final byte   FORMAT_VERSION = 0x01;
    static final int    IV_BYTES      = 12;
    static final int    TAG_BITS      = 128;   // 16-byte GCM tag
    static final int    TAG_BYTES     = 16;
    static final int    DEFAULT_CHUNK = 4096;  // plaintext bytes per chunk

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final String BC        = "BC";

    private final int         chunkSize;
    private final SecureRandom rng = new SecureRandom();

    public StreamingAesGcmEngine() {
        this(DEFAULT_CHUNK);
    }

    public StreamingAesGcmEngine(int chunkSize) {
        if (Security.getProvider(BC) == null)
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        this.chunkSize = chunkSize;
    }

    // ─────────────────────────────────────────────────────────────
    // PUBLIC API
    // ─────────────────────────────────────────────────────────────

    /**
     * Encrypt an InputStream to an OutputStream in fixed-size chunks.
     *
     * @param key           32-byte AES-256 key
     * @param plaintext     source stream (any size — S3, disk, memory)
     * @param ciphertext    destination stream
     * @throws Exception    on crypto or I/O error
     */
    public void encryptStream(byte[] key, InputStream plaintext, OutputStream ciphertext)
            throws Exception {
        validateKey(key);
        writeHeader(ciphertext);

        byte[] buf = new byte[chunkSize];
        int chunkIndex = 0;
        int n;

        while ((n = readFully(plaintext, buf)) > 0) {
            byte[] chunk = (n == chunkSize) ? buf : java.util.Arrays.copyOf(buf, n);
            encryptChunk(key, chunk, chunkIndex++, ciphertext);
        }

        writeEof(ciphertext);
        log.debug("encryptStream: {} chunks encrypted", chunkIndex);
    }

    /**
     * Decrypt a stream previously produced by {@link #encryptStream}.
     *
     * @param key           same 32-byte key used during encryption
     * @param ciphertext    source stream (output of encryptStream)
     * @param plaintext     destination stream
     * @throws Exception    if decryption or authentication fails
     */
    public void decryptStream(byte[] key, InputStream ciphertext, OutputStream plaintext)
            throws Exception {
        validateKey(key);
        readAndVerifyHeader(ciphertext);

        int chunkIndex = 0;
        while (true) {
            int chunkLen = readInt(ciphertext);
            if (chunkLen == 0) break; // EOF marker

            byte[] ivAndCt = readExactly(ciphertext, chunkLen);
            byte[] iv = java.util.Arrays.copyOfRange(ivAndCt, 0, IV_BYTES);
            byte[] ct = java.util.Arrays.copyOfRange(ivAndCt, IV_BYTES, ivAndCt.length);

            byte[] decrypted = decryptChunk(key, iv, ct, chunkIndex++);
            plaintext.write(decrypted);
        }

        log.debug("decryptStream: {} chunks decrypted", chunkIndex);
    }

    // ─────────────────────────────────────────────────────────────
    // CHUNK ENCRYPT / DECRYPT
    // ─────────────────────────────────────────────────────────────

    private void encryptChunk(byte[] key, byte[] plaintext, int chunkIndex,
                               OutputStream out) throws Exception {
        byte[] iv = new byte[IV_BYTES];
        rng.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM, BC);
        cipher.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(TAG_BITS, iv));
        // AAD: chunk index prevents reordering attacks
        cipher.updateAAD(ByteBuffer.allocate(4).putInt(chunkIndex).array());

        byte[] ct = cipher.doFinal(plaintext);

        // Write: [chunkLen 4B][IV 12B][ciphertext+tag]
        int chunkLen = IV_BYTES + ct.length;
        writeInt(out, chunkLen);
        out.write(iv);
        out.write(ct);
    }

    private byte[] decryptChunk(byte[] key, byte[] iv, byte[] ct, int chunkIndex)
            throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM, BC);
        cipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(TAG_BITS, iv));
        cipher.updateAAD(ByteBuffer.allocate(4).putInt(chunkIndex).array());
        return cipher.doFinal(ct);
    }

    // ─────────────────────────────────────────────────────────────
    // HEADER / EOF
    // ─────────────────────────────────────────────────────────────

    private void writeHeader(OutputStream out) throws IOException {
        out.write(MAGIC);
        out.write(FORMAT_VERSION);
        writeInt(out, chunkSize);
    }

    private void readAndVerifyHeader(InputStream in) throws IOException {
        byte[] magic = readExactly(in, 4);
        for (int i = 0; i < MAGIC.length; i++) {
            if (magic[i] != MAGIC[i])
                throw new IOException("Invalid stream: bad magic bytes — not a PQCS stream");
        }
        int version = in.read();
        if (version != FORMAT_VERSION)
            throw new IOException("Unsupported PQCS stream version: " + version);
        readInt(in); // skip declared chunk size — we use whatever is in each chunk
    }

    private void writeEof(OutputStream out) throws IOException {
        writeInt(out, 0); // chunkLen = 0 signals EOF
    }

    // ─────────────────────────────────────────────────────────────
    // I/O HELPERS
    // ─────────────────────────────────────────────────────────────

    private void writeInt(OutputStream out, int value) throws IOException {
        out.write((value >>> 24) & 0xFF);
        out.write((value >>> 16) & 0xFF);
        out.write((value >>>  8) & 0xFF);
        out.write( value         & 0xFF);
    }

    private int readInt(InputStream in) throws IOException {
        byte[] b = readExactly(in, 4);
        return ((b[0] & 0xFF) << 24) | ((b[1] & 0xFF) << 16)
             | ((b[2] & 0xFF) <<  8) |  (b[3] & 0xFF);
    }

    private byte[] readExactly(InputStream in, int n) throws IOException {
        byte[] buf = new byte[n];
        int read = 0;
        while (read < n) {
            int r = in.read(buf, read, n - read);
            if (r < 0) throw new IOException("Unexpected end of stream — expected " + n + " bytes");
            read += r;
        }
        return buf;
    }

    /** Read up to buf.length bytes; returns actual bytes read (0 = EOF). */
    private int readFully(InputStream in, byte[] buf) throws IOException {
        int total = 0;
        while (total < buf.length) {
            int r = in.read(buf, total, buf.length - total);
            if (r < 0) break;
            total += r;
        }
        return total;
    }

    private void validateKey(byte[] key) {
        if (key == null || key.length != 32)
            throw new IllegalArgumentException(
                    "AES-256-GCM requires exactly 32-byte key, got: "
                    + (key == null ? "null" : key.length));
    }

    public int getChunkSize() { return chunkSize; }
}
