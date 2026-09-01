## Verdict

Exploitable. The `/api/billing/**` endpoints are explicitly exempted from CSRF protection using `ignoringRequestMatchers()`, allowing state-changing requests (PATCH to `/api/billing/card`) to proceed without CSRF token validation.

## Source

An attacker crafts a malicious form or JavaScript request targeting an authenticated user's browser to update the billing card information at the `/api/billing/card` endpoint.

## Fix

**Vulnerable code (line 12):**
```java
.csrf(csrf -> csrf.ignoringRequestMatchers("/api/billing/**"))
```

**Fixed code:**
```java
.csrf()
```

The exemption for `/api/billing/**` should be removed entirely, enabling Spring Security's default CSRF protection for all endpoints including the billing API. Spring Boot enables CSRF protection by default, so omitting the configuration altogether or using `.csrf()` with no exclusions will apply the default token validation to all state-changing requests.

## Explanation

The vulnerability exists because the SecurityConfig explicitly disables CSRF protection for the billing endpoints by calling `ignoringRequestMatchers("/api/billing/**")`. This allows the BillingController's `updateCard()` method to process PATCH requests to `/api/billing/card` without validating CSRF tokens. An attacker can exploit this by tricking an authenticated user into visiting a malicious site that sends a forged request to update the user's payment card. Removing the exemption re-enables Spring Security's synchronizer token pattern (enabled by default), which requires all state-changing requests to include a valid CSRF token bound to the user's session. Requests lacking or presenting an invalid token are rejected with HTTP 403, preventing unauthorized state changes.

## Behaviour changes

1. **CSRF token requirement**: All POST, PUT, DELETE, and PATCH requests to `/api/billing/**` endpoints now require a valid CSRF token in the request (either as an `X-CSRF-TOKEN` header for AJAX calls or as a form parameter `_csrf` for form submissions). This is the correct and intended behaviour for Spring Security CSRF protection.
2. **Request rejection**: Requests to billing endpoints without a valid CSRF token will be rejected with HTTP 403 Forbidden instead of being processed. This is the security boundary closing the vulnerability.
3. **No other behaviour changes**: The fix preserves all other aspects of the security configuration (authentication requirements for all paths, session management, filter chain ordering). The sink contract is preserved: the `SecurityFilterChain` bean is still returned and configured correctly; only the CSRF filter exclusion is removed.
