package com.pqc.hybrid.config;

import com.pqc.hybrid.jwt.DilithiumJwtFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Security configuration for PqcStarterLib demo.
 *
 * Route summary:
 *   /auth/**           — public (token issuance)
 *   /api/pqc/**        — public (Phase 1/2 PQC demos)
 *   /api/encrypt/**    — public (Phase 2 encryption demos)
 *   /api/migration/**  — public (Phase 5 migration bridge demos)
 *   /api/atrest/**     — public (Phase 6 data-at-rest demos)
 *   /actuator/**       — public (monitoring)
 *   /api/secure/**     — requires a valid Dilithium-3 JWT  ← Phase 4
 *   anything else      — authenticated
 *
 * NOTE: In production, lock down actuator and remove the demo password.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final DilithiumJwtFilter dilithiumJwtFilter;

    public SecurityConfig(DilithiumJwtFilter dilithiumJwtFilter) {
        this.dilithiumJwtFilter = dilithiumJwtFilter;
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/auth/**").permitAll()
                .requestMatchers("/api/pqc/**").permitAll()
                .requestMatchers("/api/encrypt/**").permitAll()
                .requestMatchers("/api/migration/**").permitAll()
                .requestMatchers("/api/atrest/**").permitAll()
                .requestMatchers("/actuator/**").permitAll()
                .requestMatchers("/api/secure/**").authenticated()
                .anyRequest().authenticated()
            )
            .httpBasic(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            .addFilterBefore(dilithiumJwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
