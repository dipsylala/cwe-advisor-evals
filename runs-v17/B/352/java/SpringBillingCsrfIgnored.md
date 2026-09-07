## Verdict

The finding is **confirmed**. The `/api/billing/**` endpoints contain a state-changing operation (`PATCH /api/billing/card` that updates billing information) and are explicitly excluded from CSRF protection via `ignoringRequestMatchers()`. An attacker can craft a malicious request that tricks an authenticated user into modifying their billing information without their explicit consent, exploiting the absence of CSRF token validation.

## Source

**File:** SecurityConfig.java  
**Line:** 12  
**Code:** `.csrf(csrf -> csrf.ignoringRequestMatchers("/api/billing/**"))`

**Call chain:**
1. `SecurityConfig.apiSecurity()` (line 12) explicitly excludes `/api/billing/**` from CSRF protection
2. `BillingController.updateCard()` (line 16) is a `@PatchMapping` to `/api/billing/card` — a state-changing endpoint modifying billing data
3. `BillingService.queueCardUpdate()` persists the card change to backend systems

**Data flow:** An attacker-controlled HTTP PATCH request to `/api/billing/card` bypasses CSRF validation because the endpoint is in the excluded pattern. The request is processed and the card update is queued without verifying the request originated from the legitimate application.

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
            .csrf(csrf -> {})
            .build();
    }
}
```

## Explanation

The vulnerability was an explicit CSRF protection exclusion via `ignoringRequestMatchers("/api/billing/**")` that left state-changing billing endpoints unprotected. The fix removes this exclusion by replacing it with an empty lambda that uses Spring Security's default CSRF configuration: CSRF tokens are required for all POST, PUT, DELETE, and PATCH requests (non-safe HTTP methods) across all endpoints.

With this fix, Spring Security's `CsrfFilter` will:
1. Generate a unique CSRF token and bind it to the user's `HttpSession`
2. Require the token to be submitted in all state-changing requests to `/api/billing/card` (and other PATCH/POST/PUT/DELETE endpoints)
3. Validate the token using `MessageDigest.isEqual()` (constant-time comparison) before processing any billing update

The `BillingController` receives an authenticated request only after CSRF validation succeeds, preventing cross-site forgery attacks. The client must include the token either as a form parameter (`_csrf`) or as an HTTP header (`X-CSRF-TOKEN` or `X-XSRF-TOKEN` depending on token repository configuration).

## Behaviour changes

**Request handling:** PATCH requests to `/api/billing/card` without a valid CSRF token are now rejected with HTTP 403 Forbidden by Spring Security's `CsrfFilter` before the request reaches the controller. Legitimate requests must include the CSRF token in a hidden form field or request header.

**Token lifecycle:** The CSRF token is tied to the user's session. When the user logs in, a new token is issued and bound to the new session ID, invalidating any pre-authentication token that might have been leaked or cached. This prevents token reuse after session regeneration.

**Scope of protection:** CSRF protection now covers all `/api/billing/**` endpoints, not just the `/api/billing/card` PATCH endpoint. All POST, PUT, DELETE, and PATCH requests to this path prefix require valid tokens. GET requests are exempt (they do not mutate state).
