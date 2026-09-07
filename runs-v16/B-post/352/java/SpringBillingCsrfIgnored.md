## Verdict

**VULNERABLE**: CSRF protection is explicitly disabled for the `/api/billing/**` endpoints via `ignoringRequestMatchers`, allowing attackers to force authenticated users to modify their billing information without authorization.

## Source

**File**: `SecurityConfig.java`, line 12  
**Vulnerable code**:
```java
.csrf(csrf -> csrf.ignoringRequestMatchers("/api/billing/**"))
```

**Data flow**:
1. HTTP PATCH request arrives at `/api/billing/card` (defined in `BillingController.java`, line 16)
2. The `BillingController.updateCard()` method accepts the request and forwards the data to `BillingService.queueCardUpdate()`
3. `BillingService.queueCardUpdate()` processes the card update without CSRF token validation
4. The security configuration at line 12 of `SecurityConfig.java` explicitly disables CSRF protection for all `/api/billing/**` paths, leaving the endpoint unprotected

**Sink**: The state-changing PATCH endpoint processes billing card updates (`@PatchMapping("/api/billing/card")`) without CSRF token validation.

## Fix

**Vulnerable code**:
```java
@Bean
SecurityFilterChain apiSecurity(HttpSecurity http) throws Exception {
    return http
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
        .csrf(csrf -> csrf.ignoringRequestMatchers("/api/billing/**"))
        .build();
}
```

**Fixed code**:
```java
@Bean
SecurityFilterChain apiSecurity(HttpSecurity http) throws Exception {
    return http
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
        .csrf(csrf -> csrf.csrfTokenRepository(new HttpSessionCsrfTokenRepository()))
        .build();
}
```

Alternatively, if you want to explicitly show that CSRF is enabled (it is by default in Spring Boot):
```java
@Bean
SecurityFilterChain apiSecurity(HttpSecurity http) throws Exception {
    return http
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
        // CSRF protection enabled by default for all state-changing methods
        .build();
}
```

**Client-side update**: Clients calling `PATCH /api/billing/card` must include the CSRF token in the request header:
```
X-CSRF-TOKEN: <token-value>
```

The token can be retrieved from the session or a cookie, depending on the configured `CsrfTokenRepository`.

## Explanation

CSRF vulnerabilities occur when state-changing operations (POST, PATCH, PUT, DELETE) are processed without verifying that the request genuinely originated from the application. By explicitly calling `ignoringRequestMatchers("/api/billing/**")`, the configuration disables Spring Security's CSRF protection for all billing endpoints. This allows attackers to craft malicious web pages that trick authenticated users into sending requests to modify their billing information.

The fix removes the CSRF exemption, enabling Spring Security's default CSRF protection using synchronizer tokens. When CSRF protection is active, Spring Security:
1. Generates a cryptographically random token per session
2. Requires the token to be included in state-changing requests (in the request parameter or header)
3. Validates the token before processing the request
4. Rejects requests without a valid token with HTTP 403 Forbidden

For REST API clients, the CSRF token must be included in the `X-CSRF-TOKEN` request header (the default header name for Spring Security). The token is bound to the user's session and regenerated at login to prevent pre-authentication token replay.

## Behaviour changes

- **Request validation**: The `/api/billing/card` endpoint now requires a valid CSRF token in the `X-CSRF-TOKEN` header for all PATCH requests
- **Error responses**: Requests missing the token or containing an invalid token receive HTTP 403 Forbidden responses
- **Client requirements**: API clients must obtain the CSRF token from the server (typically from the session or a cookie) and include it in subsequent state-changing requests
- **Token regeneration**: The CSRF token is automatically regenerated when the session is established at login, invalidating any pre-authentication tokens
- **Session binding**: Each token is cryptographically bound to the user's session and cannot be reused across sessions
