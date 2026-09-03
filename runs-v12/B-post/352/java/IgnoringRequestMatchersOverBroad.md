## Verdict

Exploitable. The CSRF protection exclusion pattern is over-broad, disabling CSRF tokens for all `/api/**` endpoints when only `/api/webhooks/**` requires exemption. An attacker can craft a CSRF attack against authenticated, state-changing routes under `/api/` that should be protected (e.g., `/api/users/`, `/api/settings/**`) because the `ignoringRequestMatchers("/api/**")` sink at line 24 excludes them from Spring Security's CSRF filter.

## Source

Configuration class `SecurityConfig` at line 24, where the CSRF protection exclusion pattern is set.

## Fix

**Vulnerable code:**
```java
.csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"))
```

**Fixed code:**
```java
.csrf(csrf -> csrf.ignoringRequestMatchers("/api/webhooks/**"))
```

Change the exclusion pattern from the over-broad `/api/**` to the specific `/api/webhooks/**` endpoint that receives third-party webhook callbacks unable to present CSRF tokens.

## Explanation

The comment in the code establishes that `/api/webhooks/**` must sit outside the CSRF filter because third-party payment providers POST callbacks and cannot present a CSRF token. However, every other `/api/**` route is authenticated and state-changing and must keep CSRF protection. The original `ignoringRequestMatchers("/api/**")` pattern disables CSRF for the entire `/api/` namespace, leaving unrelated authenticated routes vulnerable to cross-site request forgery. The fix narrows the exclusion to only the webhook endpoint, restoring CSRF token validation for all other `/api/` routes that require it. Spring Security validates CSRF tokens on non-safe methods (POST, PUT, DELETE) via its `CsrfFilter`, using synchronizer tokens (default: `HttpSessionCsrfTokenRepository` generating tokens with `UUID.randomUUID()` and `CsrfFilter` comparing with constant-time `MessageDigest.isEqual()`), so tightening the exclusion immediately re-enables that validation for the at-risk routes.

## Behaviour changes

None. The fix is purely a security tightening. The legitimate use case—accepting third-party webhook callbacks at `/api/webhooks/**`—continues to work unchanged. All other authenticated API endpoints regain CSRF token validation, which is required for safe operation.
