## Verdict

exploitable (confidence: high)

## Source

`BillingController.updateCard` (`BillingController.java:16-20`), mapped with `@PatchMapping("/api/billing/card")`. It accepts an unauthenticated-origin `CardUpdateRequest` body (`customerId`, `token`) from any request that carries the victim's session cookie and forwards it directly to `BillingService.queueCardUpdate`, which queues a real card-token update (`BillingService.java:6-8`). This is a state-changing, authenticated action - exactly what CSRF protection exists to guard.

## Fix

Vulnerable code (`SecurityConfig.java`):

```java
package cases.csrf;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

public class SecurityConfig {
    @Bean
    SecurityFilterChain apiSecurity(HttpSecurity http) throws Exception {
        return http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .csrf(csrf -> csrf.ignoringRequestMatchers("/api/billing/**"))  // disables CSRF protection for all billing endpoints
            .build();
    }
}
```

Fixed code (`SecurityConfig.java`):

```java
package cases.csrf;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

public class SecurityConfig {
    @Bean
    SecurityFilterChain apiSecurity(HttpSecurity http) throws Exception {
        return http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .build();
    }
}
```

## Explanation

The sink is the `.csrf(csrf -> csrf.ignoringRequestMatchers("/api/billing/**"))` call: it takes Spring Security's `CsrfFilter`, which is enabled by default in Spring Boot and validates the synchronizer token on every non-safe HTTP method (including `PATCH`), and explicitly exempts every path under `/api/billing/**` from that check. `BillingController.updateCard` lives at `/api/billing/card`, so the exemption reaches exactly the card-update endpoint: a cross-site request carrying the victim's session cookie (an auto-submitting form or `fetch` from an attacker page, sent as a simple request since `PATCH` with a JSON body still needs no special CORS grant to be attempted) reaches `queueCardUpdate` with no token validation. Removing the `.csrf(...)` customizer removes the exclusion, so `HttpSecurity` falls back to its default - CSRF protection enabled, backed by `HttpSessionCsrfTokenRepository`, which mints the token with `UUID.randomUUID()` and `CsrfFilter` compares it with `MessageDigest.isEqual()` (constant-time). Any request to `/api/billing/card` that lacks a valid `_csrf` token (form field, `X-CSRF-TOKEN` header, or `X-XSRF-TOKEN` if a cookie-based repository is adopted later) is now rejected with `403 Forbidden` before it reaches `BillingController`.

## Behaviour changes

- Requests to `PATCH /api/billing/card` (and any other route under `/api/billing/**`) that do not carry a valid CSRF token now receive `403 Forbidden` instead of being processed. This is the intended effect of closing the weakness, not incidental scope creep: it is the only way a state-changing endpoint under an exempted path can be restored to CSRF protection.
- Legitimate callers of this endpoint - a server-rendered form or an authenticated AJAX/fetch client - must now include the CSRF token: the hidden `${_csrf.parameterName}`/`${_csrf.token}` pair for a form, or the `X-CSRF-TOKEN` header carrying the same value for AJAX/fetch, sourced from the session-bound token Spring Security already issues by default.
- No other request matcher, HTTP method mapping, argument, or return value was changed. `authorizeHttpRequests` and the rest of the filter chain configuration are untouched.
