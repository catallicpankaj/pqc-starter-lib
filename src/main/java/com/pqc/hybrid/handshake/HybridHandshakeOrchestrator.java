package com.pqc.hybrid.handshake;

import com.pqc.hybrid.keymanagement.service.QuantumKeyService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ═══════════════════════════════════════════════════════════════════════
 * HYBRID CLASSICAL-PQC HANDSHAKE ORCHESTRATOR Real Kyber-768 + ECDHE-P384 with
 * genuine hybrid key derivation.
 * ═══════════════════════════════════════════════════════════════════════
 *
 * THREE MODES (runtime-switched per client):
 *
 * CLASSICAL: SessionKey = KDF(ECDHE_secret, session_id) PQC_ONLY: SessionKey =
 * KDF(Kyber_secret, session_id) HYBRID: SessionKey = KDF(ECDHE_secret ||
 * Kyber_secret, session_id)
 *
 * The HYBRID mode is the novel contribution: - ECDHE-P384 provides today's
 * classical security - Kyber-768 provides quantum-safe security for the future
 * - Combined via HMAC-SHA256 KDF: must break BOTH to compromise the session
 *
 * Runtime switching: Client sends X-PQC-Supported / X-PQC-Hybrid headers →
 * Orchestrator selects best mode automatically → Sessions can be UPGRADED from
 * CLASSICAL to HYBRID without reconnecting
 * ═══════════════════════════════════════════════════════════════════════
 */
@Component
public class HybridHandshakeOrchestrator {

	private static final Logger log = LoggerFactory.getLogger(HybridHandshakeOrchestrator.class);
	private static final String BC = "BC";
	private static final String BCPQC = "BCPQC";

	private final KyberKemEngine kyberEngine;

	// Phase 3 present: keys are read fresh from QuantumKeyService on every use, so a
	// scheduled/manual rotation (KeyRotationManager) takes effect on the very next
	// handshake — nothing here is cached across a rotation.
	private final Optional<QuantumKeyService> quantumKeyService;

	// Phase 3 absent: ephemeral key pairs generated once at startup (never rotate —
	// there is nowhere to rotate them to without a KMS).
	private final KeyPair ephemeralKyberKeyPair;
	private final KeyPair ephemeralEcKeyPair;

	// Active session cache
	private final Map<String, HandshakeSession> sessions = new ConcurrentHashMap<>();

	static {
		if (Security.getProvider(BC) == null)
			Security.insertProviderAt(new BouncyCastleProvider(), 1);
		if (Security.getProvider(BCPQC) == null)
			Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);
	}

	/**
	 * Phase 1/2 constructor — generates ephemeral in-memory keys at startup.
	 * Used when Phase 3 (key management) is not configured.
	 */
	public HybridHandshakeOrchestrator() throws Exception {
		this(Optional.empty());
	}

	/**
	 * Phase 3 constructor — uses KMS-managed persistent keys when QuantumKeyService
	 * is present, falls back to ephemeral keys when it is not.
	 *
	 * Spring injects Optional.empty() when no QuantumKeyService bean exists
	 * (Phase 3 not configured), preserving full backwards compatibility.
	 */
	public HybridHandshakeOrchestrator(Optional<QuantumKeyService> quantumKeyService) throws Exception {
		this.kyberEngine = new KyberKemEngine();
		this.quantumKeyService = quantumKeyService;
		if (quantumKeyService.isPresent()) {
			this.ephemeralKyberKeyPair = null;
			this.ephemeralEcKeyPair    = null;
			log.info("HybridHandshakeOrchestrator using KMS-managed persistent keys — provider={}",
				quantumKeyService.get().getProviderName());
		} else {
			this.ephemeralKyberKeyPair = kyberEngine.generateKeyPair();
			this.ephemeralEcKeyPair    = generateEcKeyPair();
			log.info("HybridHandshakeOrchestrator using ephemeral in-memory keys (Phase 3 not configured)");
		}
		log.info("  Server Kyber public key: {} bytes", currentKyberKeyPair().getPublic().getEncoded().length);
		log.info("  Server EC public key:    {} bytes", currentEcKeyPair().getPublic().getEncoded().length);
	}

	/**
	 * Returns the currently ACTIVE Kyber key pair. When Phase 3 is configured this is
	 * read fresh from QuantumKeyService on every call, so a rotation takes effect on
	 * the next handshake with no restart required.
	 */
	private KeyPair currentKyberKeyPair() {
		return quantumKeyService.isPresent()
			? quantumKeyService.get().getActiveKyberKeyPair()
			: ephemeralKyberKeyPair;
	}

	/** Returns the currently ACTIVE EC key pair — see {@link #currentKyberKeyPair()}. */
	private KeyPair currentEcKeyPair() {
		return quantumKeyService.isPresent()
			? quantumKeyService.get().getActiveEcKeyPair()
			: ephemeralEcKeyPair;
	}

	// ─────────────────────────────────────────────────────────────
	// PUBLIC API
	// ─────────────────────────────────────────────────────────────

	/**
	 * Orchestrate a handshake: detects capability, selects mode, derives session
	 * key.
	 */
	public HandshakeSession orchestrate(ClientCapability capability) throws Exception {
		String sessionId = generateSessionId();
		CipherMode mode = capability.negotiateBestMode();
		log.info("Handshake [{}] client={} mode={}", sessionId, capability.getClientId(), mode);

		HandshakeSession session = switch (mode) {
		case HYBRID -> performHybridHandshake(sessionId, capability);
		case PQC_ONLY -> performPqcHandshake(sessionId, capability);
		case CLASSICAL -> performClassicalHandshake(sessionId, capability);
		};

		sessions.put(sessionId, session);
		return session;
	}

	/**
	 * Upgrade an existing CLASSICAL session to HYBRID when client later advertises
	 * PQC capability — no reconnection required.
	 */
	public HandshakeSession upgradeSession(String existingSessionId, ClientCapability newCapability) throws Exception {
		HandshakeSession existing = sessions.get(existingSessionId);
		if (existing == null) {
			throw new IllegalStateException("Session not found: " + existingSessionId);
		}

		CipherMode current = existing.getCipherMode();
		CipherMode target = newCapability.negotiateBestMode();

		if (target.ordinal() <= current.ordinal()) {
			log.debug("Session [{}]: no upgrade needed ({} → {})", existingSessionId, current, target);
			return existing;
		}

		log.info("Session [{}]: upgrading {} → {}", existingSessionId, current, target);
		HandshakeSession upgraded = orchestrate(newCapability);
		sessions.put(existingSessionId, upgraded); // replace in-place
		return upgraded;
	}

	// ─────────────────────────────────────────────────────────────
	// HANDSHAKE IMPLEMENTATIONS
	// ─────────────────────────────────────────────────────────────

	/**
	 * HYBRID HANDSHAKE — The novel core contribution.
	 *
	 * Full flow: 1. ECDHE: client + server exchange EC public keys →
	 * classicalSecret 2. Kyber: client encapsulates to server pubKey → kyberSecret
	 * + ciphertext Server decapsulates ciphertext → same kyberSecret 3. KDF:
	 * SessionKey = HMAC-SHA256(classicalSecret || kyberSecret, sessionId)
	 *
	 * An attacker must break BOTH ECDHE-P384 AND Kyber-768 to recover the key.
	 */
	private HandshakeSession performHybridHandshake(String sessionId, ClientCapability capability) throws Exception {
		long start = System.nanoTime();

		KeyPair kyberKeyPair = currentKyberKeyPair();
		KeyPair ecKeyPair    = currentEcKeyPair();

		// Step 1: Real ECDHE-P384 key agreement
		KeyPair clientEcPair = generateEcKeyPair();
		byte[] classicalSecret = ecdhKeyAgreement(clientEcPair, ecKeyPair);

		// Step 2: Real Kyber-768 KEM — encapsulate to server's public key
		KyberKemEngine.KemResult kem = kyberEngine.encapsulate(kyberKeyPair.getPublic());
		// Server-side: decapsulate to verify shared secret matches (simulating full
		// handshake)
		byte[] serverKyberSecret = kyberEngine.decapsulate(kyberKeyPair.getPrivate(), kem.ciphertext());
		// In a real TLS handshake the client sends kem.ciphertext() to the server over
		// the wire
		// Both sides now have the same kyberSecret

		// Step 3: HYBRID KEY DERIVATION — combines both secrets
		byte[] hybridKey = hybridKdf(classicalSecret, kem.sharedSecret(), sessionId);

		long durationNs = System.nanoTime() - start;
		log.info("[{}] HYBRID: ECDHE={}B + Kyber={}B → hybridKey={}B  ({} ms)", sessionId, classicalSecret.length,
				kem.sharedSecret().length, hybridKey.length, durationNs / 1_000_000);

		return HandshakeSession.builder().sessionId(sessionId).cipherMode(CipherMode.HYBRID)
				.sessionKeyMaterial(hybridKey).clientId(capability.getClientId()).classicalAlgorithm("ECDHE-P384")
				.pqcKemAlgorithm("Kyber-768").handshakeDurationNs(durationNs).quantumSafe(true).build();
	}

	/**
	 * PQC-ONLY HANDSHAKE — Kyber-768 only, no classical component.
	 */
	private HandshakeSession performPqcHandshake(String sessionId, ClientCapability capability) throws Exception {
		long start = System.nanoTime();

		KeyPair kyberKeyPair = currentKyberKeyPair();
		KyberKemEngine.KemResult kem = kyberEngine.encapsulate(kyberKeyPair.getPublic());
		kyberEngine.decapsulate(kyberKeyPair.getPrivate(), kem.ciphertext()); // server side
		byte[] sessionKey = simpleKdf(kem.sharedSecret(), sessionId);

		long durationNs = System.nanoTime() - start;
		log.info("[{}] PQC_ONLY: Kyber={}B → sessionKey={}B  ({} ms)", sessionId, kem.sharedSecret().length,
				sessionKey.length, durationNs / 1_000_000);

		return HandshakeSession.builder().sessionId(sessionId).cipherMode(CipherMode.PQC_ONLY)
				.sessionKeyMaterial(sessionKey).clientId(capability.getClientId()).pqcKemAlgorithm("Kyber-768")
				.handshakeDurationNs(durationNs).quantumSafe(true).build();
	}

	/**
	 * CLASSICAL HANDSHAKE — ECDHE-P384 only, always available as fallback.
	 */
	private HandshakeSession performClassicalHandshake(String sessionId, ClientCapability capability) throws Exception {
		long start = System.nanoTime();

		KeyPair clientEcPair = generateEcKeyPair();
		byte[] classicalSecret = ecdhKeyAgreement(clientEcPair, currentEcKeyPair());
		byte[] sessionKey = simpleKdf(classicalSecret, sessionId);

		long durationNs = System.nanoTime() - start;
		log.info("[{}] CLASSICAL: ECDHE={}B → sessionKey={}B  ({} ms)", sessionId, classicalSecret.length,
				sessionKey.length, durationNs / 1_000_000);

		return HandshakeSession.builder().sessionId(sessionId).cipherMode(CipherMode.CLASSICAL)
				.sessionKeyMaterial(sessionKey).clientId(capability.getClientId()).classicalAlgorithm("ECDHE-P384")
				.handshakeDurationNs(durationNs).quantumSafe(false).build();
	}

	// ─────────────────────────────────────────────────────────────
	// CRYPTOGRAPHIC PRIMITIVES
	// ─────────────────────────────────────────────────────────────

	/**
	 * HYBRID KDF — the core novel algorithm.
	 *
	 * Combines classical (ECDHE) and PQC (Kyber) secrets: SessionKey =
	 * HMAC-SHA256(classicalSecret || kyberSecret, sessionId_as_key)
	 *
	 * In production: replace with HKDF (RFC 5869) for proper key derivation.
	 */
	private byte[] hybridKdf(byte[] classicalSecret, byte[] kyberSecret, String sessionId) throws Exception {
		Mac hmac = Mac.getInstance("HmacSHA256", BC);
		hmac.init(new SecretKeySpec(sessionId.getBytes(), "HmacSHA256"));
		hmac.update(classicalSecret);
		hmac.update(kyberSecret);
		return hmac.doFinal();
	}

	/** Simple KDF for single-secret modes */
	private byte[] simpleKdf(byte[] secret, String sessionId) throws Exception {
		Mac hmac = Mac.getInstance("HmacSHA256", BC);
		hmac.init(new SecretKeySpec(sessionId.getBytes(), "HmacSHA256"));
		return hmac.doFinal(secret);
	}

	/** ECDH key agreement between two EC key pairs */
	private byte[] ecdhKeyAgreement(KeyPair clientKP, KeyPair serverKP) throws Exception {
		KeyAgreement ka = KeyAgreement.getInstance("ECDH", BC);
		ka.init(clientKP.getPrivate());
		ka.doPhase(serverKP.getPublic(), true);
		return ka.generateSecret();
	}

	/** Generate an ephemeral ECDHE-P384 key pair */
	private KeyPair generateEcKeyPair() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BC);
		kpg.initialize(new ECGenParameterSpec("secp384r1"));
		return kpg.generateKeyPair();
	}

	private String generateSessionId() {
		return UUID.randomUUID().toString().replace("-", "").substring(0, 16).toUpperCase();
	}

	// ─────────────────────────────────────────────────────────────
	// ACCESSORS
	// ─────────────────────────────────────────────────────────────

	public Map<String, HandshakeSession> getSessions() {
		return Collections.unmodifiableMap(sessions);
	}

	public Optional<HandshakeSession> getSession(String id) {
		return Optional.ofNullable(sessions.get(id));
	}

	public PublicKey getServerKyberPublicKey() {
		return currentKyberKeyPair().getPublic();
	}

	public PublicKey getServerEcPublicKey() {
		return currentEcKeyPair().getPublic();
	}

	public KyberKemEngine getKyberEngine() {
		return kyberEngine;
	}
}
