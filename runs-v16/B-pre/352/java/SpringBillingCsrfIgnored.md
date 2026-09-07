## Verdict
exploitable

## Source
Untrusted HTTP PATCH request to `/api/billing/card` from an external domain with an authenticated user's session cookies.

## Fix

### Vulnerable Code
```java
public class SecurityConfig {
    @Bean
    SecurityFilterChain apiSecurity(HttpSecurity http) throws Exception {
        return http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .csrf(csrf -> csrf.ignoringRequestMatchers("/api/billing/**"))  // CSRF protection disabled for billing API
            .build();
    }
}
```

### Fixed Code
```java
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
The vulnerability exists because the SecurityConfig explicitly disables CSRF protection for all `/api/billing/**` endpoints using `ignoringRequestMatchers()`. The BillingController exposes a `@PatchMapping("/api/billing/card")` endpoint that performs a state-changing operation (updating a customer's billing card). An attacker can craft a malicious request that exploits an authenticated user's session to modify their billing information without authorization.

The fix removes the `.csrf(csrf -> csrf.ignoringRequestMatchers("/api/billing/**"))` configuration entirely. Spring Security enables CSRF protection by default in Spring Boot applications, so this allows the default CSRF filter to protect the `/api/billing/**` endpoints. All PATCH requests to `/api/billing/card` will now require a valid CSRF token. Clients must include the CSRF token in the request, either as a form parameter `_csrf` with the token value, or for AJAX requests, in the `X-CSRF-TOKEN` or `X-XSRF-TOKEN` header depending on the token repository configuration.

## Behaviour changes
- State-changing requests to `/api/billing/**` endpoints now require a valid CSRF token and will be rejected with 403 Forbidden if the token is missing or invalid.
- Client applications must be updated to extract the CSRF token from the response (or session attribute) and include it in subsequent PATCH/POST/PUT/DELETE requests.
- Pre-authentication tokens cannot be replayed after session login due to Spring's default session regeneration behavior, which re-issues the CSRF token.
- The default Spring Security CSRF token is generated using `UUID.randomUUID()` and compared using constant-time comparison, preventing timing attacks.
