## Verdict

The code is vulnerable to CWE-352 (Cross-Site Request Forgery). The CSRF protection is misconfigured for an SPA: the cookie handler and token request handler are mismatched, allowing CSRF attacks because the token validation is not properly enforced.

## Source

File: `SecurityConfig.java`, line 26

The vulnerable code configures only the CSRF token repository without explicitly configuring the token request handler:
```java
.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
```

This creates a security gap where the CSRF token is stored in a cookie but the request handler may not properly validate it on incoming requests.

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
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

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
                .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(org.springframework.security.config.http.SessionCreationPolicy.IF_REQUIRED));

        return http.build();
    }
}
```

## Explanation

The vulnerability exists because the CSRF configuration only specifies the token repository but does not explicitly configure the token request handler. In Spring Security, the CSRF token repository (where the token is stored) and the CSRF token request handler (how the token is validated in requests) must be properly aligned.

For SPAs that use cookies to store CSRF tokens:

1. **Token Storage**: `CookieCsrfTokenRepository.withHttpOnlyFalse()` correctly stores the token in a non-httpOnly cookie so JavaScript can read it.

2. **Token Validation**: Without an explicit `csrfTokenRequestHandler`, the validation mechanism may not properly enforce the CSRF token requirement on state-changing requests (POST, PUT, DELETE).

The fix adds `CsrfTokenRequestAttributeHandler()`, which ensures:
- The CSRF token sent by the client in request headers is properly validated
- The token must match the value stored in the cookie
- Any mismatch results in request rejection

This resolves the handler mismatch and ensures CSRF protection is properly enforced for all state-changing operations, preventing attackers from forging requests on behalf of authenticated users.

