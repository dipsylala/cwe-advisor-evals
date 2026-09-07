## Verdict
CONFIRMED. The CSRF token cookie is stored with `HttpOnly=false`, allowing JavaScript to access it. This violates CWE-352 defenses: XSS vulnerabilities can steal the token, and the cookie lacks additional protections (SameSite) that mitigate the exposure of a JavaScript-accessible token.

## Source
Line 26 of SecurityConfig.java:
```
.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
```

The `withHttpOnlyFalse()` call explicitly disables the HttpOnly flag that prevents JavaScript from accessing the CSRF token cookie. While a single-page application requires JavaScript to read the token to echo it on state-changing requests, the architecture shown here exposes the token to theft via XSS.

## Fix

### File: SecurityConfig.java
```java
package com.example.accounts.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

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
                .csrfTokenRepository(new CookieCsrfTokenRepository())
                .csrfTokenRequestHandler(new org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler()))
            .sessionManagement(session -> session
                .sessionCreationPolicy(org.springframework.security.config.http.SessionCreationPolicy.IF_REQUIRED));

        return http.build();
    }
}
```

## Explanation
The vulnerability arises from disabling the HttpOnly flag on the CSRF token cookie. This allows JavaScript to access the token, which creates an attack surface for XSS: any XSS payload can read and exfiltrate the token.

The fix replaces `CookieCsrfTokenRepository.withHttpOnlyFalse()` with `new CookieCsrfTokenRepository()`, which uses the secure default of `HttpOnly=true`. The token cookie is now inaccessible to JavaScript, preventing XSS attacks from stealing it.

For an SPA to access the token, Spring Security's `CsrfTokenRequestAttributeHandler` places the token in a request attribute. The SPA can retrieve it from a dedicated endpoint or by intercepting the server's initial response to read a `X-CSRF-TOKEN` header (or equivalent) that the framework sends alongside the cookie. The frontend then reads the token from the header and echoes it back in subsequent requests; the HttpOnly cookie is sent automatically by the browser and validated server-side.

This approach preserves the SPA's ability to perform CSRF token exchange while removing the vulnerability of exposing the token to JavaScript and XSS.
