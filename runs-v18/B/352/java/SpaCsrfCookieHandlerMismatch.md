## Verdict

CONFIRMED. The configuration enables CSRF token cookie access for JavaScript (`withHttpOnlyFalse()`) but fails to pair it with a `SpaCsrfTokenRequestHandler`, causing a token encoding mismatch. Spring Security's default `XorCsrfTokenRequestAttributeHandler` BREACH-encodes tokens server-side, making the raw cookie value sent by JavaScript never match the encoded value compared by CsrfFilter. All legitimate state-changing requests from the SPA are rejected with 403 Forbidden.

## Source

**File**: SecurityConfig.java  
**Line**: 26  
**Sink**: `.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))`

The vulnerability is in the SecurityFilterChain configuration where CSRF protection is enabled. The code configures `CookieCsrfTokenRepository.withHttpOnlyFalse()` to allow JavaScript to read the CSRF token from cookies (per the SPA pattern documented in the code comments), but does not configure a matching token request handler. The AccountController's `@PatchMapping("/api/account/profile")` endpoint sends the X-XSRF-TOKEN header with the raw cookie value, which CsrfFilter compares against the BREACH-encoded server-side value, causing a mismatch.

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
                .csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler()))
            .sessionManagement(session -> session
                .sessionCreationPolicy(org.springframework.security.config.http.SessionCreationPolicy.IF_REQUIRED));

        return http.build();
    }
}
```

## Explanation

The fix pairs `CookieCsrfTokenRepository.withHttpOnlyFalse()` with `SpaCsrfTokenRequestHandler`, as required by Spring Security 6.0+ for Single Page Applications that read CSRF tokens from cookies.

**What changed**: Added `.csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler())` and added the required import for `SpaCsrfTokenRequestHandler`.

**Why it eliminates the weakness**: 
- `SpaCsrfTokenRequestHandler` (built-in to Spring Security 7.x) handles the token encoding/decoding symmetrically, ensuring the value JavaScript reads from the cookie and sends back matches the value CsrfFilter validates
- This replaces the default `XorCsrfTokenRequestAttributeHandler` which BREACH-encodes tokens server-side, creating the mismatch
- The raw cookie value JavaScript sends via the X-XSRF-TOKEN header now matches the value stored in the session, allowing CsrfFilter to validate the request successfully
- State-changing requests (POST, PUT, DELETE, PATCH) from the SPA are now properly validated instead of being rejected with 403

The `SpaCsrfTokenRequestHandler` is available in Spring Security 7.x as a built-in class. For Spring Security 6.x users, this same class can be implemented as a custom component following Spring Security's Single Page Application sample in the reference documentation.

## Behaviour changes

- Legitimate CSRF token submissions from the SPA in the X-XSRF-TOKEN header now pass validation instead of failing with 403
- The `/api/account/profile` endpoint (and any other state-changing endpoints) can now successfully process authenticated requests from the SPA frontend
- No changes to the token generation, storage, or session binding semantics; the fix only corrects the validation handler to match the client-side token transmission method
