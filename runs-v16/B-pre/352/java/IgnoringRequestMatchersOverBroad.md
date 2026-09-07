## Verdict

exploitable

## Source

Spring Security configuration in `SecurityConfig.apiSecurity()` bean: the developer intends to exempt only `/api/webhooks/**` from CSRF protection (third-party webhooks cannot present tokens), but the configuration at line 24 exempts the entire `/api/**` namespace instead.

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

The vulnerability lies in an over-broad `ignoringRequestMatchers()` pattern. Line 24 disables CSRF token validation for all routes matching `/api/**`, which includes every API endpoint—not just the webhook endpoints that lack token support. This allows attackers to forge requests to any state-changing API endpoint from an authenticated user's browser session. The fix narrows the exemption from `/api/**` to `/api/webhooks/**`, which is the specific path that third-party payment providers need to bypass for callbacks. All other authenticated state-changing endpoints under `/api/**` will now enforce CSRF token validation as intended by the original code comments (lines 13–16).

## Behaviour changes

All API routes except `/api/webhooks/**` will now require valid CSRF tokens for POST, PUT, DELETE, and PATCH requests. Third-party webhook callbacks can still bypass token validation as designed for their use case.

