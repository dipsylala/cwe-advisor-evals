## Verdict
Confirmed. `SecurityConfig.apiSecurity()` explicitly disables CSRF protection for `/api/billing/**` via `csrf.ignoringRequestMatchers("/api/billing/**")`, while `BillingController.updateCard()` exposes a state-changing `PATCH /api/billing/card` endpoint that queues a payment-card update using only `authorizeHttpRequests(...).authenticated()` for protection. Spring Security's default authentication mechanism is session/cookie based, and cookies are sent automatically by the browser on cross-site requests, so with CSRF checks turned off for this path a forged cross-site request from an authenticated victim's browser can trigger a card update the victim never intended (CWE-352).

## Source
- `evals/cases/352/java/SpringBillingCsrfIgnored/SecurityConfig.java:12` - `csrf.ignoringRequestMatchers("/api/billing/**")` disables Spring Security's default CSRF protection for the entire billing API path.
- `evals/cases/352/java/SpringBillingCsrfIgnored/BillingController.java:16-20` - `PATCH /api/billing/card` is a state-changing endpoint (`updateCard`) that reaches `billingService.queueCardUpdate(...)`, sitting directly under the excluded path.
- `evals/cases/352/java/SpringBillingCsrfIgnored/BillingService.java:6-8` - `queueCardUpdate` performs the sensitive action (queues a card/token update), confirming the endpoint is a genuine CSRF target, not a read-only operation.

## Fix
```java
package cases.csrf;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

public class SecurityConfig {
    @Bean
    SecurityFilterChain apiSecurity(HttpSecurity http) throws Exception {
        return http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
            .build();
    }
}
```

Remove the `ignoringRequestMatchers("/api/billing/**")` call entirely so CSRF protection applies uniformly, including to the billing endpoints. Since this is a REST API (no server-rendered forms), pair the built-in `CsrfFilter` with `CookieCsrfTokenRepository.withHttpOnlyFalse()` so the SPA/API client can read the XSRF token from the `XSRF-TOKEN` cookie and echo it back in the `X-XSRF-TOKEN` request header on every state-changing call (`PATCH`, `POST`, `PUT`, `DELETE`); the default `HttpSessionCsrfTokenRepository` works too but requires the client to first fetch the token from a page or endpoint that renders it, which most pure-API clients don't do. If the app instead moves to fully stateless authentication (e.g. a bearer JWT validated per request with no session cookie and no cookie-based auth of any kind), CSRF protection can legitimately be disabled and `SessionCreationPolicy.STATELESS` set - but that is not what this configuration does today, since no such stateless auth mechanism is configured here.

## Explanation
Spring Security enables CSRF protection by default for any `HttpSecurity` chain; an explicit `csrf(...)` customizer is only needed to change that default, and here it was used to carve out an exemption instead. Excluding a request-matcher from CSRF checks is appropriate for endpoints that either don't rely on ambient browser credentials (pure bearer-token/API-key auth) or that are inherently non-state-changing (webhooks with their own signature verification, public GET endpoints). `/api/billing/card` is neither: it's authenticated by whatever default mechanism `authorizeHttpRequests` sits on top of - which, absent an `oauth2ResourceServer` or `SessionCreationPolicy.STATELESS` override, is Spring Security's cookie/session-backed authentication - and it performs a sensitive write (queuing a payment card token update). A cross-site `<form>` or `fetch` request from an unrelated origin will still carry the victim's session cookie automatically, so removing the CSRF exemption (and supplying a token-repository the API client can actually use) closes the gap without weakening the endpoint's authentication requirement. Verify the fix by issuing the `PATCH` from a cross-origin page without the `X-XSRF-TOKEN` header and confirming Spring Security now returns `403 Forbidden`, then confirming the request succeeds when the client reads the `XSRF-TOKEN` cookie and sends it back in that header.
