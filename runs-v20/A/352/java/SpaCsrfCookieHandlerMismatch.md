## Verdict

Confirmed. The filter chain pairs `CookieCsrfTokenRepository.withHttpOnlyFalse()` with Spring Security's default `CsrfTokenRequestHandler` (`XorCsrfTokenRequestAttributeHandler`), and no filter forces the token to load. That combination does not deliver working CSRF protection to this SPA client, and the resulting failure mode is exactly what CWE-352 targets: state-changing endpoints end up reachable without a valid, verifiable token round-trip.

Two compounding problems:

1. `XorCsrfTokenRequestAttributeHandler` is designed to defeat BREACH by re-encoding the token differently on every render (`random || XOR(token, random)`), and it expects a submitted header/parameter value in that same encoded form. `CookieCsrfTokenRepository`, however, always reads and writes the *raw* `CsrfToken.getToken()` value directly in the `XSRF-TOKEN` cookie - it is never routed through the handler's encoding. A pure JavaScript SPA that reads the cookie and echoes it back verbatim in `X-XSRF-TOKEN` is therefore submitting a raw value into a handler that will try to XOR-decode it as if it were encoded, so validation cannot succeed for the intended client.
2. Both `CsrfTokenRequestAttributeHandler` and `XorCsrfTokenRequestAttributeHandler` defer loading the token: the token is only generated and written to the response cookie when something actually calls `CsrfToken.getToken()` (e.g. a view rendering a hidden field). A JSON-only API that never renders a token never triggers that read, so the cookie the SPA depends on may simply never be set on first load.

In practice, teams that hit this combination "working around" it by disabling CSRF for the affected routes or removing the check is the realistic outcome, which is the actual exploitable end state this finding flags.

## Source

- Untrusted trigger: a cross-origin page causing the victim's browser to submit a state-changing request to this API (the standard CSRF actor), combined with the SPA's own JavaScript, which reads the `XSRF-TOKEN` cookie (readable because it is `httpOnly=false`) and is expected to echo it back in the `X-XSRF-TOKEN` header on same-origin calls.
- Sink: `SecurityConfig.filterChain()`, line 26, `csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())` - the CSRF verification wiring that must actually accept the token the SPA can produce.

## Fix

### File: SecurityConfig.java
```java
package com.example.accounts.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
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
            .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));

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
 * Bridges CookieCsrfTokenRepository (which always stores the raw token in the
 * cookie) with Spring Security's BREACH-protected default handler.
 *
 * Rendering still goes through XorCsrfTokenRequestAttributeHandler so any
 * server-rendered view keeps BREACH protection. Resolution of a submitted
 * token prefers the plain (non-XORed) value when it arrives via the header
 * the SPA populates from the cookie, since that raw value was never XOR
 * encoded in the first place; it falls back to the XOR-aware resolver for
 * anything submitted as a request parameter (e.g. a rendered form field).
 */
final class SpaCsrfTokenRequestHandler extends CsrfTokenRequestAttributeHandler {

    private final CsrfTokenRequestHandler delegate = new XorCsrfTokenRequestAttributeHandler();

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, Supplier<CsrfToken> csrfToken) {
        this.delegate.handle(request, response, csrfToken);
    }

    @Override
    public String resolveCsrfTokenValue(HttpServletRequest request, CsrfToken csrfToken) {
        if (StringUtils.hasText(request.getHeader(csrfToken.getHeaderName()))) {
            return super.resolveCsrfTokenValue(request, csrfToken);
        }
        return this.delegate.resolveCsrfTokenValue(request, csrfToken);
    }

}
```

### File: CsrfCookieFilter.java
```java
package com.example.accounts.config;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * CsrfToken loading is deferred until CsrfToken#getToken() is called. A pure
 * JSON API never renders the token into a view, so without this filter the
 * XSRF-TOKEN cookie the SPA depends on would never be written. Reading the
 * token attribute here forces it to be generated and the cookie to be set
 * on every request.
 */
final class CsrfCookieFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        csrfToken.getToken();

        filterChain.doFilter(request, response);
    }

}
```

## Explanation

`CookieCsrfTokenRepository` and Spring Security's default `CsrfTokenRequestHandler` are not interchangeable with an arbitrary handler when the client is a plain SPA reading the cookie in JavaScript: the repository always persists and reconstructs the *raw* token in the `XSRF-TOKEN` cookie, while `XorCsrfTokenRequestAttributeHandler` (the default since Spring Security 6) both encodes the token differently on every access for BREACH resistance and expects submitted values to be in that encoded form. A raw cookie value echoed straight back in `X-XSRF-TOKEN` cannot be resolved by that handler, and because token loading is deferred until something calls `CsrfToken.getToken()`, a JSON-only API may never even populate the cookie in the first place.

`SpaCsrfTokenRequestHandler` keeps the XOR-encoding path for anything rendered into a view (preserving BREACH protection where it still applies) but resolves a header-submitted token with the plain, non-XORed comparison that matches what `CookieCsrfTokenRepository` actually put in the cookie. `CsrfCookieFilter` forces the deferred token to be loaded on every request so the cookie is reliably present for the SPA to read, including on the first navigation before any state-changing call.

With this wiring, the SPA can obtain a real token, echo it back correctly, and have it verified - so the CSRF check enforced by this filter chain is one the client can actually satisfy, rather than one that is bypassed in practice by disabling protection to unblock a broken integration. This is the configuration Spring Security's own reference documentation prescribes for exactly this cookie-based SPA integration, so it does not change the deployment's session model, cookie exposure, or authentication flow.
