package com.pqc.hybrid.handshake;

import java.util.Set;

/**
 * Cryptographic capabilities advertised by a connecting client.
 *
 * Clients signal PQC support via HTTP headers: X-PQC-Supported:
 * Kyber-768,Dilithium-3 X-PQC-Hybrid: true X-PQC-Version: 1 X-PQC-Session:
 * &lt;existing-session-id&gt; (for session upgrades)
 */
public class ClientCapability {

	public static final String HEADER_PQC_SUPPORTED = "X-PQC-Supported";
	public static final String HEADER_PQC_HYBRID = "X-PQC-Hybrid";
	public static final String HEADER_PQC_VERSION = "X-PQC-Version";
	public static final String HEADER_PQC_SESSION_ID = "X-PQC-Session";

	private final boolean pqcCapable;
	private final boolean hybridCapable;
	private final Set<String> supportedAlgorithms;
	private final int protocolVersion;
	private final String clientId;

	private ClientCapability(Builder b) {
		this.pqcCapable = b.pqcCapable;
		this.hybridCapable = b.hybridCapable;
		this.supportedAlgorithms = b.supportedAlgorithms;
		this.protocolVersion = b.protocolVersion;
		this.clientId = b.clientId;
	}

	/**
	 * Determine the best cipher mode for this client — core of runtime switching
	 */
	public CipherMode negotiateBestMode() {
		if (!pqcCapable)
			return CipherMode.CLASSICAL;
		if (hybridCapable && (supports("Kyber-768") || supports("ML-KEM-768")))
			return CipherMode.HYBRID;
		if (pqcCapable)
			return CipherMode.PQC_ONLY;
		return CipherMode.CLASSICAL;
	}

	public boolean isPqcCapable() {
		return pqcCapable;
	}

	public boolean isHybridCapable() {
		return hybridCapable;
	}

	public Set<String> getSupportedAlgorithms() {
		return supportedAlgorithms;
	}

	public int getProtocolVersion() {
		return protocolVersion;
	}

	public String getClientId() {
		return clientId;
	}

	public boolean supports(String algo) {
		return supportedAlgorithms.contains(algo);
	}

	public static Builder builder() {
		return new Builder();
	}

	public static class Builder {
		private boolean pqcCapable = false;
		private boolean hybridCapable = false;
		private Set<String> supportedAlgorithms = Set.of();
		private int protocolVersion = 0;
		private String clientId = "unknown";

		public Builder pqcCapable(boolean v) {
			pqcCapable = v;
			return this;
		}

		public Builder hybridCapable(boolean v) {
			hybridCapable = v;
			return this;
		}

		public Builder supportedAlgorithms(Set<String> v) {
			supportedAlgorithms = v;
			return this;
		}

		public Builder protocolVersion(int v) {
			protocolVersion = v;
			return this;
		}

		public Builder clientId(String v) {
			clientId = v;
			return this;
		}

		public ClientCapability build() {
			return new ClientCapability(this);
		}
	}
}
