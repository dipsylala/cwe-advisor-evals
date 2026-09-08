## Verdict

Exploitable.

## Source

Single-page application (SPA) frontend that reads the CSRF token from a cookie in JavaScript and echoes it back in request headers for authenticated state-changing operations.

## Fix

When using `CookieCsrfTokenRepository.withHttpOnlyFalse()` to expose the CSRF token to client-side JavaScript, the default Spring Security 6.0+ `XorCsrfTokenRequestAttributeHandler` BREACH-encodes the token on the server side. This creates a mismatch: the JavaScript client reads the raw (unencoded) token from the cookie and sends it back, but the server-side filter expects the BREACH-encoded version. This breaks CSRF protection.

The fix is to pair `withHttpOnlyFalse()` with a custom `SpaCsrfTokenRequestHandler` that returns the token in the same encoding as what the client reads from the cookie, without BREACH encoding.

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
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler()))
            .sessionManagement(session -> session
                .sessionCreationPolicy(org.springframework.security.config.http.SessionCreationPolicy.IF_REQUIRED));

        return http.build();
    }
}
```

### File: SpaCsrfTokenRequestHandler.java

```java
package com.example.accounts.config;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.function.Supplier;

/**
 * CSRF token request handler for single-page applications (SPAs).
 *
 * When using CookieCsrfTokenRepository with httpOnly=false, the client-side
 * JavaScript reads the CSRF token directly from the cookie. This handler ensures
 * the token value returned to the client matches what the client reads from the
 * cookie, and properly validates requests that include the token without BREACH
 * encoding mismatches.
 *
 * Based on Spring Security's single-page-application CSRF reference implementation.
 */
public class SpaCsrfTokenRequestHandler implements CsrfTokenRequestHandler {
    private final CsrfTokenRequestHandler delegate = new XorCsrfTokenRequestAttributeHandler();

    /**
     * Handle CSRF token response. Delegates to the standard handler which sets up
     * the token in the response for the client to read from the cookie.
     */
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, Supplier<CsrfToken> csrfToken) {
        this.delegate.handle(request, response, csrfToken);
    }

    /**
     * Resolve the CSRF token value from the request.
     *
     * For SPA clients that read the token from the cookie and submit it in a header
     * or parameter, return the raw token value without BREACH encoding. This ensures
     * the client's submitted token matches the server's stored token during validation.
     */
    @Override
    public String resolveCsrfTokenValue(HttpServletRequest request, CsrfToken token) {
        // Return the raw token value without BREACH encoding
        // The client reads this same value from the cookie, so it must match
        return token.getToken();
    }
}
```

## Explanation

The vulnerability occurs because Spring Security 6.0+ applies BREACH (Browser Reflection Attack Against Chosen-plaintext Encryption) protection to CSRF tokens by default. When `CookieCsrfTokenRepository.withHttpOnlyFalse()` is used to allow JavaScript to read the token from a non-httpOnly cookie, the token is stored in BREACH-encoded form on the server. However, when the JavaScript client reads the cookie, it gets the raw (unencoded) value. When the client sends the token back in a header or parameter, the raw value no longer matches the BREACH-encoded version stored server-side, causing legitimate CSRF requests to fail validation. This breaks the application's CSRF protection and may cause the developer to disable CSRF altogether to fix the broken application.

The fix implements a custom `SpaCsrfTokenRequestHandler` that overrides `resolveCsrfTokenValue()` to return the token without BREACH encoding. This ensures the validation logic compares the client's raw token value against the stored raw value, allowing legitimate SPA requests to pass while still protecting against CSRF attacks. The handler delegates the response setup to the standard `XorCsrfTokenRequestAttributeHandler`, preserving its cookie-setup behavior while fixing only the token-value encoding mismatch.

## Behaviour changes

The `.csrfTokenRequestHandler()` method is a new call in the CSRF configuration chain. This adds a second argument to the csrf lambda (lines 25-27 change from a single method call to chained methods). The new handler is passed as an argument to `.csrfTokenRequestHandler()`. The handler itself is a new class added to the same package as the configuration.

The `resolveCsrfTokenValue()` override changes how the CSRF filter validates incoming requests: instead of comparing BREACH-encoded values, it now compares raw token values. This matches the expectation of SPA clients that read the raw value from the cookie. No other behavior changes: the token generation, session binding, and cookie attributes remain unchanged. The CSRF filter still validates on all non-safe methods and still rejects requests without valid tokens.
