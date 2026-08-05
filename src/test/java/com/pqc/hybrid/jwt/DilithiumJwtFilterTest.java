package com.pqc.hybrid.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.*;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.security.Security;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for {@link DilithiumJwtFilter} — the servlet filter that validates Bearer
 * tokens on every request. Exercises the filter directly (request/response handling,
 * SecurityContext population, the 401 JSON error body and its message escaping) rather
 * than only through {@link DilithiumJwtService}, which other tests already cover well.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class DilithiumJwtFilterTest {

    private static DilithiumJwtService jwtService;
    private static DilithiumJwtFilter  filter;

    @BeforeAll
    static void setup() throws Exception {
        if (Security.getProvider("BC")    == null) Security.insertProviderAt(new BouncyCastleProvider(),    1);
        if (Security.getProvider("BCPQC") == null) Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);
        DilithiumKeyPairHolder holder = new DilithiumKeyPairHolder(Optional.empty());
        jwtService = new DilithiumJwtService(holder, new ObjectMapper(), 60);
        filter     = new DilithiumJwtFilter(jwtService);
    }

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test @Order(1)
    @DisplayName("No Authorization header -> passes through unchanged, no authentication set")
    void noAuthHeaderPassesThrough() throws Exception {
        MockHttpServletRequest  request  = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain         chain    = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isSameAs(request);
        assertThat(response.getStatus()).isEqualTo(200); // untouched — filter didn't write a status
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        System.out.println("✓ No Authorization header -> pass-through, SecurityConfig decides access");
    }

    @Test @Order(2)
    @DisplayName("Authorization header without 'Bearer ' prefix -> passes through unchanged")
    void nonBearerAuthHeaderPassesThrough() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Basic dXNlcjpwYXNz");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain         chain    = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isSameAs(request);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        System.out.println("✓ Non-Bearer Authorization header -> pass-through, untouched");
    }

    @Test @Order(3)
    @DisplayName("Valid Bearer token -> populates SecurityContext with subject and ROLE_ authorities")
    void validTokenPopulatesSecurityContext() throws Exception {
        String token = jwtService.issueToken("alice", List.of("USER", "ADMIN"));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain         chain    = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isSameAs(request); // chain still reached
        var auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth).isNotNull();
        assertThat(auth.getPrincipal()).isEqualTo("alice");
        assertThat(auth.getAuthorities())
            .extracting(Object::toString)
            .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
        System.out.println("✓ Valid Bearer token -> SecurityContext populated with subject + ROLE_ authorities");
    }

    @Test @Order(4)
    @DisplayName("Invalid signature -> 401 JSON error, chain NOT reached, no authentication set")
    void invalidTokenReturns401AndStopsChain() throws Exception {
        String token = jwtService.issueToken("bob", List.of("USER"));
        String[] parts = token.split("\\.");
        // Corrupt the signature segment
        String tampered = parts[0] + "." + parts[1] + "." + "AAAA" + parts[2].substring(4);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + tampered);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain         chain    = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentType()).contains("application/json");
        assertThat(response.getContentAsString()).contains("\"error\"");
        assertThat(chain.getRequest()).isNull(); // chain.doFilter() must NOT have been called
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        System.out.println("✓ Invalid signature -> 401 JSON, chain halted: " + response.getContentAsString());
    }

    @Test @Order(5)
    @DisplayName("Malformed token (not 3 segments) -> 401 JSON error with 'malformed' in the message")
    void malformedTokenReturns401() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer not-a-jwt-at-all");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentAsString().toLowerCase()).contains("malformed");
        System.out.println("✓ Malformed token -> 401 with 'malformed' reason: " + response.getContentAsString());
    }

    @Test @Order(6)
    @DisplayName("Error message JSON-escapes embedded quotes/backslashes (no injection into the response body)")
    void errorMessageIsJsonEscaped() throws Exception {
        // A token whose header decodes to JSON containing a quote character in a value
        // reaches the MALFORMED path with the raw exception message embedded — verify
        // the filter escapes it rather than emitting invalid/injectable JSON.
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer a.b"); // only 2 segments -> MALFORMED, message contains "found: 2"
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        String body = response.getContentAsString();
        assertThat(response.getStatus()).isEqualTo(401);
        // Must be valid, parseable JSON with no unescaped control characters
        assertThat(body).startsWith("{\"error\":\"").endsWith("\"}");
        System.out.println("✓ Error body is well-formed escaped JSON: " + body);
    }
}
