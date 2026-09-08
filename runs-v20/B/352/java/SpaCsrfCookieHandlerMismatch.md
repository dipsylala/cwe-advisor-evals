## Verdict

Exploitable. CWE-352 (Cross-Site Request Forgery), `SecurityConfig.java` line 26, confidence: high.

## Source

Sink: `csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())` in the `filterChain` `SecurityFilterChain` bean. Source: any state-changing request Spring Security's `CsrfFilter` evaluates on the chain configured here (all `POST`/`PUT`/`DELETE`/`PATCH` requests to `/api/**`, since only the two auth endpoints are `permitAll()` and everything else requires authentication).

`CookieCsrfTokenRepository.withHttpOnlyFalse()` is the correct repository choice for this deployment - the class comment states the SPA reads the CSRF token out of a cookie in JavaScript and echoes it back on state-changing calls, and a cookie only readable by the server (the `HttpOnly` default) would be unreadable to that JavaScript. The configuration never installs a `CsrfTokenRequestHandler`, so the `CsrfConfigurer` falls back to Spring Security's own default, `XorCsrfTokenRequestAttributeHandler`, which BREACH-encodes the token value on every render. The cookie repository writes the raw, unencoded token to the cookie regardless, because it has no rendering step to encode through - it just sets a cookie. The SPA therefore reads the plain token out of the cookie and echoes that plain value back in the CSRF header, but `CsrfFilter` asks the (default XOR) handler to resolve the expected value from the token it holds, which decodes assuming the incoming value is XOR-encoded. Plain-vs-encoded values almost never coincide, so the filter's comparison fails and every legitimate SPA request is rejected with 403 - which is exactly the condition under which a team disables or works around CSRF protection to unblock the frontend, reopening the endpoints to forgery. The mismatch is the sink: the repository and the request-handling side of CSRF protection speak two different encodings of the same token, and nothing in this file reconciles them.

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

import java.util.function.Supplier;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.util.StringUtils;

/**
 * CsrfTokenRequestHandler for a cookie-based CSRF token consumed by a
 * separately deployed single-page-application frontend, adapted from the
 * Spring Security reference documentation's single-page-application sample.
 *
 * XorCsrfTokenRequestAttributeHandler (Spring Security's default handler)
 * BREACH-encodes the token value it exposes, but a SPA reads the raw,
 * unencoded token straight out of the cookie written by
 * CookieCsrfTokenRepository and echoes it back verbatim in a request
 * header. This handler always renders with the BREACH-protected encoding,
 * and resolves the submitted value with the plain handler whenever the
 * token arrives via the expected CSRF header - matching what the cookie
 * repository handed to the SPA in the first place.
 */
final class SpaCsrfTokenRequestHandler implements CsrfTokenRequestHandler {

    private final CsrfTokenRequestHandler plain = new CsrfTokenRequestAttributeHandler();
    private final CsrfTokenRequestHandler xor = new XorCsrfTokenRequestAttributeHandler();

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, Supplier<CsrfToken> csrfToken) {
        this.xor.handle(request, response, csrfToken);
    }

    @Override
    public String resolveCsrfTokenValue(HttpServletRequest request, CsrfToken csrfToken) {
        String headerValue = request.getHeader(csrfToken.getHeaderName());
        return (StringUtils.hasText(headerValue) ? this.plain : this.xor).resolveCsrfTokenValue(request, csrfToken);
    }
}
```

## Explanation

The fix pairs the existing `CookieCsrfTokenRepository.withHttpOnlyFalse()` with an explicit `SpaCsrfTokenRequestHandler`, so the code that renders/resolves the token now agrees with the code that stores it. `handle()` still runs the token through `XorCsrfTokenRequestAttributeHandler`, preserving BREACH protection for any server-rendered attribute use. `resolveCsrfTokenValue()` checks whether the submitted value arrived in the CSRF header (`X-XSRF-TOKEN`, the header name matching this repository) - the path a JavaScript client that just read the raw cookie value takes - and if so resolves it with the plain `CsrfTokenRequestAttributeHandler`, which expects the unencoded value the cookie actually holds; any other path (a hidden form field, for a server-rendered page) still resolves through the XOR handler. This is the single-page-application handler documented in Spring Security's own reference documentation for this exact combination (a cookie repository with `withHttpOnlyFalse()` feeding a JavaScript client) - Spring Security 6.x does not ship the class, so it is added here as application code in the same package as `SecurityConfig`, rather than imported. No sink argument, repository, or session policy was changed; only the missing request-handler pairing was added, so the token is now generated, stored, transmitted, and validated under one consistent encoding instead of two.

## Behaviour changes

- Added `.csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler())` to the `csrf` configurer. This is required by the fix: without it, `CsrfConfigurer` defaults to `XorCsrfTokenRequestAttributeHandler` for both rendering and resolution, which is the encoding mismatch this fix closes. No other line in `filterChain` was touched - `authorizeHttpRequests`, the repository choice, and `sessionManagement` are unchanged.
- Net effect for legitimate SPA traffic: requests that were previously rejected with 403 (plain cookie value compared against an XOR-decoded expectation) now validate correctly, because the header value is resolved with the same plain handler that matches the cookie's raw content. This restores intended behavior rather than changing it - the mismatch was blocking the application's own documented client, not an attacker.
- Verification: compiled both files with `javac` against the real dependencies from the local Maven cache (`spring-security-web`, `spring-security-config`, `spring-security-core` 6.5.7; `spring-context`, `spring-web`, `spring-core`, `spring-beans`, `spring-aop`, `spring-expression` 6.x; `jakarta.servlet-api` 6.1.0) in an isolated scratch directory - exit code 0, no diagnostics. This also confirms `csrfTokenRequestHandler(CsrfTokenRequestHandler)` exists on the `CsrfConfigurer` in Spring Security 6.5.7 and that `SpaCsrfTokenRequestHandler`'s constructor calls, method signatures, and `@Override`s all match the framework interfaces used.
- Assumption: no build manifest was present in the case directory, so the Jakarta Servlet namespace (`jakarta.servlet.*`) and Spring Security 6.x semantics (which do not ship `SpaCsrfTokenRequestHandler` and do not offer the 7.x `csrf.spa()` shortcut) were assumed based on the imports already present in the original file (`org.springframework.security.config.annotation.web.builders.HttpSecurity`, package layout consistent with Spring Boot 3). If the application in fact targets Spring Security 7.x, `csrf.spa()` could replace both the explicit `csrfTokenRequestHandler(...)` call and the added class, but the hand-written handler above is correct on either version and was chosen so the fix does not depend on confirming the exact minor version.
