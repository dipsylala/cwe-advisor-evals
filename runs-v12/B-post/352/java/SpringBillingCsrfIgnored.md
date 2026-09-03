## Verdict

Exploitable. CSRF protection is explicitly disabled via `ignoringRequestMatchers()` for endpoints that perform state-changing operations. An attacker can trick an authenticated user into submitting a PATCH request to `/api/billing/card` from a malicious website, allowing unauthorized billing card updates.

## Source

BillingController.java, line 16-20: The `@PatchMapping("/api/billing/card")` endpoint accepts a `CardUpdateRequest` containing sensitive billing information (customerId, token) without CSRF token validation. This endpoint matches the `/api/billing/**` pattern that is excluded from CSRF protection.

## Fix

**Vulnerable code (SecurityConfig.java, lines 10-13):**
```java
return http
    .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
    .csrf(csrf -> csrf.ignoringRequestMatchers("/api/billing/**"))
    .build();
```

**Fixed code (SecurityConfig.java, lines 10-12):**
```java
return http
    .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
    .build();
```

Remove the `.csrf(csrf -> csrf.ignoringRequestMatchers("/api/billing/**"))` configuration to enable Spring's default CSRF protection for all state-changing endpoints, including `/api/billing/card`. Spring Security's CSRF filter is enabled by default and will require valid CSRF tokens for all non-safe HTTP methods (POST, PUT, PATCH, DELETE).

For the JSON API client (BillingController), the caller must send the CSRF token in the `X-CSRF-TOKEN` header with each PATCH request. This is standard practice for REST APIs protected by Spring Security's CSRF filter.

## Explanation

The removed line explicitly exempted the `/api/billing/**` paths from CSRF protection, allowing an attacker to forge cross-site requests that would be accepted by the server if the user was already authenticated. The endpoint performs a sensitive state change (updating billing card information), which requires CSRF token validation to ensure the request originated from the application itself, not from an attacker-controlled site.

By removing the exemption, Spring Security's default CSRF protection takes effect. The framework will validate that incoming PATCH requests to `/api/billing/card` include a valid CSRF token (sent via the `X-CSRF-TOKEN` header for JSON payloads). Requests without a matching token will be rejected with a 403 Forbidden response, preventing forged requests from succeeding.

## Behaviour changes

None. Spring Security's CSRF filter validates tokens only for non-safe HTTP methods (POST, PUT, PATCH, DELETE). The removal preserves the existing behavior of requiring authentication (via `.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())`) while adding CSRF token validation. No parameters are added or removed, return values are unchanged, and the security filter chain continues to function identically except for the now-enabled CSRF protection.
