## Verdict

exploitable (confidence: high)

- CWE-352 - Cross-Site Request Forgery (CSRF)
- Location: `SecurityConfig.java:12`, `csrf.ignoringRequestMatchers("/api/billing/**")`

## Source

The request itself is the source: any authenticated browser session holding a cookie for this application. `SecurityConfig.apiSecurity` requires authentication (`authorizeHttpRequests(auth -> auth.anyRequest().authenticated())`) but explicitly exempts every path under `/api/billing/**` from Spring Security's CSRF filter (`csrf(csrf -> csrf.ignoringRequestMatchers("/api/billing/**"))`). `BillingController.updateCard` is mapped to `@PatchMapping("/api/billing/card")`, which falls inside that exempted prefix, and it mutates state by forwarding `customerId` and `token` to `BillingService.queueCardUpdate`, which queues a card-token update. Because the route matches the CSRF exclusion, `CsrfFilter` never runs for it, so the handler is a state-changing, non-safe-method (PATCH) endpoint that accepts a request bearing only the ambient session cookie, with no synchronizer-token check. A cross-origin page can issue this PATCH (e.g. via `fetch` with `credentials: "include"`, or a same-effect auto-submitting form for a non-JSON variant) and have it processed as the victim, because the browser attaches the session cookie automatically and the server performs no origin/token verification before invoking `queueCardUpdate`.

Sink contract established before the fix (`CsrfFilter`, gated by `ignoringRequestMatchers`):
- Returns: nothing directly to application code - it either forwards the request down the chain or rejects it with `403 Forbidden` when the token is missing/invalid.
- Discards: none relevant here.
- Arguments left implicit: the matcher list controls which requests skip validation entirely; the code passes `/api/billing/**`, which is the entire billing API surface, not a narrower safe-method or explicitly-reviewed exception.
- Failure behaviour: with the exclusion removed, a request to `/api/billing/**` without a valid CSRF token is rejected with `403 Forbidden` before reaching `BillingController`.

## Fix

### File: SecurityConfig.java

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

The vulnerability is the over-broad `ignoringRequestMatchers("/api/billing/**")` exclusion, not a missing token generator or a weak comparison - Spring Security's default `HttpSessionCsrfTokenRepository` and `CsrfFilter` already mint and compare tokens correctly; this configuration simply told the filter to skip the entire billing API. The fix removes that exclusion and the now-empty `csrf(...)` customizer, leaving Spring Security's CSRF protection at its Boot default (enabled for all non-safe methods on every path). `CsrfFilter` now runs for `PATCH /api/billing/card`, so an authenticated card-update request must carry a valid, session-bound CSRF token or be rejected with 403, closing the forged cross-origin request path while leaving the authorization rule (`anyRequest().authenticated()`) and the handler's behaviour on a legitimate, token-bearing request unchanged.

## Behaviour changes

- Removed the `csrf(csrf -> csrf.ignoringRequestMatchers("/api/billing/**"))` customizer entirely rather than narrowing its matcher, because the guidance's taint sink for this CWE in Java is precisely "an over-broad `ignoringRequestMatchers(...)` exclusion" and no part of the billing API is a safe-method or otherwise-justified exception; there is no legitimate remaining case for excluding this prefix.
- `PATCH /api/billing/card` (and any other route under `/api/billing/**`) now requires a valid CSRF token on every request. A same-origin browser client that already renders Spring Security's `_csrf` token (e.g. from `CsrfToken` in the model, or reading the `XSRF-TOKEN` cookie if `CookieCsrfTokenRepository` is configured elsewhere) and sends it as `X-CSRF-TOKEN`/`X-XSRF-TOKEN` continues to work; any existing caller that was relying on the exemption to call this endpoint without a token (e.g. a non-browser service using only the session cookie, or a test harness) will now receive `403 Forbidden` until it is updated to include the token. This is the intended effect of closing the CSRF gap and is not otherwise avoidable.
- No sink arguments, return values, or the authorization rule were changed - `authorizeHttpRequests(...).build()` is unchanged, and `BillingController`/`BillingService` were not modified.
- Verification: no compiler with Spring Security's dependency jars on the classpath was reachable in this environment (a background filesystem search for `spring-security-*.jar` found none within the time available), so the fix was checked by manual review instead: the diff is a strict removal of one lambda-based `HttpSecurity` customizer call with no new imports, methods, or identifiers introduced; every remaining method call (`authorizeHttpRequests`, `anyRequest`, `authenticated`, `build`) is unchanged from the original file, and the method signature, `@Bean` annotation, and package/imports are untouched, so no caller in `BillingController`/`BillingService` is affected by the change.
