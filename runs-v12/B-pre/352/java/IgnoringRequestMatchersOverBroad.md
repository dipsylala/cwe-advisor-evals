## Verdict

Exploitable. The CSRF protection is disabled for an overly broad set of endpoints (`/api/**`), exposing authenticated state-changing operations to cross-site request forgery attacks. The exclusion should apply only to the webhook endpoint (`/api/webhooks/**`) that genuinely cannot provide CSRF tokens; all other `/api/**` routes are authenticated and state-changing and must retain CSRF protection.

## Source

Authenticated requests to `/api/**` endpoints that are state-changing (POST, PUT, DELETE operations), excluding only `/api/webhooks/**`. An attacker crafts a request that exploits an authenticated user's session to perform unwanted state changes on these endpoints, relying on the disabled CSRF filter to pass the request through without token validation.

## Fix

**Vulnerable code (line 24):**
```java
.csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"))
```

**Fixed code:**
```java
.csrf(csrf -> csrf.ignoringRequestMatchers("/api/webhooks/**"))
```

## Explanation

The fix narrows the CSRF protection exclusion from the entire `/api/**` tree to only `/api/webhooks/**`, the endpoint where third-party payment providers POST callbacks and cannot present a CSRF token. All other authenticated API endpoints (`/api/users/**`, `/api/orders/**`, etc.) retain Spring Security's CSRF filter, which will now require and validate synchronizer tokens for all non-safe HTTP methods (POST, PUT, DELETE). This restores the intended security boundary: only the endpoint that has a legitimate reason to bypass CSRF protection (the webhook that is intentionally permitting unauthenticated access) is excluded, while state-changing operations on authenticated endpoints remain protected.

## Behaviour changes

None. The fix preserves the existing behavior for authenticated endpoints (they now enforce CSRF protection as originally intended) and for the webhook endpoint (it remains accessible without a token, as required by the third-party integration). No method signatures, return values, or exception handling change.
