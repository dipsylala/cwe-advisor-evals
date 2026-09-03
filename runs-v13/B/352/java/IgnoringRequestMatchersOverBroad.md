## Verdict

Exploitable. The `.csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"))` pattern disables CSRF protection for all API endpoints, including authenticated and state-changing operations that require the protection. Attackers can forge state-changing requests to any `/api/**` endpoint from malicious sites visited by authenticated users, without CSRF token validation.

## Source

Attacker-controlled request issued from a cross-origin context, targeting authenticated endpoints under `/api/**` that perform state changes (POST, PUT, DELETE, PATCH).

## Fix

**Vulnerable code:**
```java
.csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"))
```

**Fixed code:**
```java
.csrf(csrf -> csrf.ignoringRequestMatchers("/api/webhooks/**"))
```

## Explanation

The overly broad pattern `/api/**` exempts all API endpoints from CSRF protection, when only the webhook endpoint `/api/webhooks/**` should be exempt (because third-party payment providers POST callbacks without CSRF tokens). By narrowing the exclusion to `/api/webhooks/**` alone, CSRF protection remains enabled for all other `/api/**` endpoints—particularly authenticated, state-changing operations—ensuring that requests to those endpoints must carry a valid CSRF token. This aligns the implementation with the stated security intent in the comment and closes the CSRF exposure.

## Behaviour changes

None. The fix preserves the sink contract: Spring Security's CSRF filter continues to validate tokens on non-exempt endpoints, and only the webhook endpoints are excluded from that validation, as intended.
