package com.example.accounts;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

// Spring Boot's security starter wires up authentication automatically, but it does not
// activate @PreAuthorize/@PostAuthorize/@Secured enforcement on its own. That requires
// @EnableMethodSecurity on a configuration class, which this application never adds -
// every @PreAuthorize annotation in the codebase is therefore evaluated by nothing and
// has no effect on whether the annotated method actually runs.
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .anyRequest().authenticated()
            );
        return http.build();
    }
}
