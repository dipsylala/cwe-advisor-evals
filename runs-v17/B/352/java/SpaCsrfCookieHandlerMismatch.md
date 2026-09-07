## Verdict

The finding is confirmed. The CSRF protection configuration has a handler mismatch that causes legitimate SPA requests to be rejected with 403 Forbidden.

## Source

The vulnerability is in SecurityConfig.java, line 26. The configuration enables cookie-based CSRF token storage for a Single-Page Application:

```java
.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
```

The issue: `CookieCsrfTokenRepository.withHttpOnlyFalse()` makes tokens readable to JavaScript so the SPA can echo them back in headers. However, the default CSRF request handler (`XorCsrfTokenRequestAttributeHandler` in Spring Security 6.0+) applies BREACH-encoding to tokens sent to the client. When the SPA reads the raw cookie value and sends it back, it doesn't match the BREACH-encoded token the server expects, causing all legitimate PATCH/POST/DELETE requests to fail validation.

The data flow:
1. Server generates CSRF token
2. `CookieCsrfTokenRepository` stores it in a readable cookie
3. Server encodes the token with `XorCsrfTokenRequestAttributeHandler` before sending to client
4. JavaScript reads the raw cookie value
5. JavaScript sends it back in X-XSRF-TOKEN header
6. Server compares the raw value against the BREACH-encoded value stored server-side
7. Mismatch → 403 Forbidden

## Fix

Add `SpaCsrfTokenRequestHandler` to the CSRF configuration to ensure tokens are handled consistently (same encoding) between client and server.

### File: SecurityConfig.java

```java
package com.example.accounts.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.SpaCsrfTokenRequestHandler;

/**
 * Security configuration for the accounts API, consumed by a separately
 * deployed single-page-application frontend. The SPA reads the CSRF token
 * out of a cookie in JavaScript and echoes it back on state-changing calls.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/login", "/api/auth/register").permitAll()
                .anyRequest().authenticated())
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .requestHandler(new SpaCsrfTokenRequestHandler()))
            .sessionManagement(session -> session
                .sessionCreationPolicy(org.springframework.security.config.http.SessionCreationPolicy.IF_REQUIRED));

        return http.build();
    }
}
```

## Explanation

The fix adds `.requestHandler(new SpaCsrfTokenRequestHandler())` to the CSRF configuration chain. `SpaCsrfTokenRequestHandler` (available in Spring Security 6.1+) is specifically designed to handle SPA clients that read CSRF tokens from cookies and send them back via headers.

Unlike the default `XorCsrfTokenRequestAttributeHandler`, which applies BREACH-encoding to protect against compression-based attacks, `SpaCsrfTokenRequestHandler` uses a different encoding strategy (`CsrfTokenRequestAttributeHandler`) that ensures the value JavaScript reads from the cookie matches what the server validates. This eliminates the encoding mismatch that was causing legitimate requests to fail.

The change is minimal and surgical: it only adds the handler configuration, preserving all other security settings (authentication requirements, session management, permitAll paths).

## Behaviour changes

**Before the fix**: Every PATCH request from the SPA with a CSRF token is rejected with 403 Forbidden, even though the token is valid and correctly sent. The SPA cannot perform state-changing operations (e.g., profile updates via PATCH /api/account/profile).

**After the fix**: PATCH requests with correctly submitted CSRF tokens are accepted and processed. The SPA can now successfully execute state-changing operations. Requests without valid tokens are still rejected (proper CSRF protection is maintained).
