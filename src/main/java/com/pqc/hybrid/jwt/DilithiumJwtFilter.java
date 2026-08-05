package com.pqc.hybrid.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Spring Security filter that validates Dilithium-3 signed JWT tokens on every request.
 *
 * FLOW:
 *   1. Extract "Authorization: Bearer <token>" from the request header.
 *   2. Call DilithiumJwtService.validateToken() — checks structure, Dilithium-3 signature, expiry.
 *   3. On success: populate SecurityContextHolder with the authenticated principal + roles.
 *   4. On any failure: write a 401 JSON error and stop the filter chain.
 *
 * Requests without an Authorization header are passed through unchanged (Spring Security's
 * access rules in SecurityConfig decide whether the endpoint requires authentication).
 *
 * This filter is registered in PqcAutoConfiguration and added to the security filter chain
 * in SecurityConfig before UsernamePasswordAuthenticationFilter.
 */
public class DilithiumJwtFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(DilithiumJwtFilter.class);
    private static final String BEARER_PREFIX = "Bearer ";

    private final DilithiumJwtService jwtService;

    public DilithiumJwtFilter(DilithiumJwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest  request,
                                    HttpServletResponse response,
                                    FilterChain         chain) throws ServletException, IOException {

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        // No Authorization header — pass through; SecurityConfig decides if auth is required
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(BEARER_PREFIX.length()).trim();

        try {
            DilithiumJwt jwt = jwtService.validateToken(token);

            List<SimpleGrantedAuthority> authorities = jwt.roles().stream()
                .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
                .toList();

            UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken(jwt.subject(), null, authorities);

            SecurityContextHolder.getContext().setAuthentication(auth);
            log.debug("Authenticated request: sub={} roles={}", jwt.subject(), jwt.roles());

        } catch (DilithiumJwtException e) {
            log.debug("JWT validation failed [{}]: {}", e.getReason(), e.getMessage());
            sendUnauthorized(response, e.getReason().name().toLowerCase() + ": " + e.getMessage());
            return;
        }

        chain.doFilter(request, response);
    }

    private void sendUnauthorized(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"error\":\"" + escape(message) + "\"}");
    }

    private String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
