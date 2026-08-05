package com.pqc.hybrid.filter;

import com.pqc.hybrid.handshake.HandshakeSession;
import com.pqc.hybrid.handshake.HybridHandshakeOrchestrator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.*;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockFilterChain;

import java.security.Security;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for {@link HybridHandshakeFilter} — the servlet filter that runs on every
 * request. Exercises header parsing directly against the filter (not indirectly
 * through the orchestrator/service it wraps), including the malformed-input and
 * exception-fallback paths that no other test touches.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class HybridHandshakeFilterTest {

    private static HybridHandshakeOrchestrator orchestrator;
    private static HybridHandshakeFilter       filter;

    @BeforeAll
    static void setup() throws Exception {
        if (Security.getProvider("BC")    == null) Security.insertProviderAt(new BouncyCastleProvider(),    1);
        if (Security.getProvider("BCPQC") == null) Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);
        orchestrator = new HybridHandshakeOrchestrator(Optional.empty());
        filter       = new HybridHandshakeFilter(orchestrator);
    }

    @Test @Order(1)
    @DisplayName("No X-PQC-* headers -> negotiates CLASSICAL, sets response headers and request attributes")
    void noHeadersNegotiatesClassical() throws Exception {
        MockHttpServletRequest  request  = new MockHttpServletRequest("GET", "/api/pqc/status");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain         chain    = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getHeader("X-PQC-Mode")).isEqualTo("CLASSICAL");
        assertThat(response.getHeader("X-PQC-Quantum-Safe")).isEqualTo("false");
        assertThat(response.getHeader("X-PQC-Session-Id")).isNotBlank();
        assertThat(request.getAttribute(HybridHandshakeFilter.ATTR_SESSION)).isInstanceOf(HandshakeSession.class);
        assertThat(request.getAttribute(HybridHandshakeFilter.ATTR_QUANTUM_SAFE)).isEqualTo(false);
        assertThat(chain.getRequest()).isSameAs(request); // chain.doFilter() was reached
        System.out.println("✓ No headers -> CLASSICAL, request attributes set, chain continues");
    }

    @Test @Order(2)
    @DisplayName("X-PQC-Supported only -> negotiates PQC_ONLY")
    void supportedHeaderOnlyNegotiatesPqcOnly() throws Exception {
        MockHttpServletRequest  request  = new MockHttpServletRequest("GET", "/api/pqc/status");
        request.addHeader("X-PQC-Supported", "Kyber-768");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getHeader("X-PQC-Mode")).isEqualTo("PQC_ONLY");
        assertThat(response.getHeader("X-PQC-Quantum-Safe")).isEqualTo("true");
        System.out.println("✓ X-PQC-Supported only -> PQC_ONLY");
    }

    @Test @Order(3)
    @DisplayName("X-PQC-Supported + X-PQC-Hybrid: true -> negotiates HYBRID")
    void bothHeadersNegotiateHybrid() throws Exception {
        MockHttpServletRequest  request  = new MockHttpServletRequest("GET", "/api/pqc/status");
        request.addHeader("X-PQC-Supported", "Kyber-768,Dilithium-3");
        request.addHeader("X-PQC-Hybrid", "true");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getHeader("X-PQC-Mode")).isEqualTo("HYBRID");
        assertThat(response.getHeader("X-PQC-Algorithm")).isEqualTo("Kyber-768");
        assertThat(response.getHeader("X-PQC-Classical")).isEqualTo("ECDHE-P384");
        System.out.println("✓ X-PQC-Supported + X-PQC-Hybrid=true -> HYBRID");
    }

    @Test @Order(4)
    @DisplayName("Blank X-PQC-Supported header is treated as no capability -> CLASSICAL")
    void blankSupportedHeaderTreatedAsAbsent() throws Exception {
        MockHttpServletRequest  request  = new MockHttpServletRequest("GET", "/api/pqc/status");
        request.addHeader("X-PQC-Supported", "");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getHeader("X-PQC-Mode")).isEqualTo("CLASSICAL");
        System.out.println("✓ Blank X-PQC-Supported -> treated as absent -> CLASSICAL");
    }

    @Test @Order(5)
    @DisplayName("Malformed X-PQC-Version (non-numeric) does not fail the request — silently ignored")
    void malformedVersionHeaderIgnored() throws Exception {
        MockHttpServletRequest  request  = new MockHttpServletRequest("GET", "/api/pqc/status");
        request.addHeader("X-PQC-Supported", "Kyber-768");
        request.addHeader("X-PQC-Version", "not-a-number");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain         chain    = new MockFilterChain();

        filter.doFilter(request, response, chain);

        // Request still proceeds normally — malformed version doesn't block or error
        assertThat(response.getHeader("X-PQC-Mode")).isEqualTo("PQC_ONLY");
        assertThat(chain.getRequest()).isSameAs(request);
        System.out.println("✓ Malformed X-PQC-Version silently ignored, request proceeds");
    }

    @Test @Order(6)
    @DisplayName("X-PQC-Session references an unknown session ID -> falls back gracefully, does not 500")
    void unknownSessionIdFallsBackGracefully() throws Exception {
        MockHttpServletRequest  request  = new MockHttpServletRequest("GET", "/api/pqc/status");
        request.addHeader("X-PQC-Supported", "Kyber-768");
        request.addHeader("X-PQC-Session", "nonexistent-session-id-12345");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain         chain    = new MockFilterChain();

        filter.doFilter(request, response, chain);

        // orchestrator.upgradeSession() throws for an unknown ID — filter must catch it
        // and fall back to CLASSICAL rather than propagating a 500.
        assertThat(response.getHeader("X-PQC-Mode")).isEqualTo("CLASSICAL");
        assertThat(response.getHeader("X-PQC-Fallback")).isEqualTo("true");
        assertThat(response.getHeader("X-PQC-Quantum-Safe")).isEqualTo("false");
        assertThat(chain.getRequest()).isSameAs(request); // chain still continues, no exception thrown out
        System.out.println("✓ Unknown X-PQC-Session ID -> graceful CLASSICAL fallback, X-PQC-Fallback=true");
    }

    @Test @Order(7)
    @DisplayName("Request attributes carry the correct CipherMode enum, not just a String")
    void requestAttributeCarriesCipherModeEnum() throws Exception {
        MockHttpServletRequest  request  = new MockHttpServletRequest("GET", "/api/pqc/status");
        request.addHeader("X-PQC-Supported", "Kyber-768");
        request.addHeader("X-PQC-Hybrid", "true");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        Object mode = request.getAttribute(HybridHandshakeFilter.ATTR_CIPHER_MODE);
        assertThat(mode).isEqualTo(com.pqc.hybrid.handshake.CipherMode.HYBRID);
        System.out.println("✓ pqc.cipher.mode request attribute is the CipherMode enum value");
    }
}
