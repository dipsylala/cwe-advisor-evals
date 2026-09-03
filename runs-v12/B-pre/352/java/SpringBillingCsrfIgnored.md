## Verdict

Exploitable

## Source

An attacker at a different origin (e.g., attacker.com) crafts a request to `/api/billing/card` while the victim is logged into the application. The browser includes the victim's session cookies with the cross-origin request.

## Fix

**Vulnerable code (SecurityConfig.java, line 12):**
```java
.csrf(csrf -> csrf.ignoringRequestMatchers("/api/billing/**"))
```

**Fixed code (SecurityConfig.java):**
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

The vulnerability arises because the CSRF protection is explicitly disabled for the `/api/billing/**` path using `ignoringRequestMatchers()`. This allows the `/api/billing/card` PATCH endpoint—which modifies sensitive billing information—to accept requests without CSRF token validation.

The fix removes the `.csrf()` configuration line entirely, allowing Spring Security's default CSRF protection to apply. This ensures that state-changing operations (POST, PUT, PATCH, DELETE) require a valid CSRF token. The application must be updated to include CSRF tokens in requests: either as a hidden field in forms (parameterName `_csrf` with the token value), or in the `X-CSRF-TOKEN` header for AJAX requests. Spring Security will validate the token before processing the request, preventing attackers from forging requests on behalf of authenticated users.

## Behaviour changes

- **CSRF token requirement**: All state-changing requests to `/api/billing/**` (including `/api/billing/card`) now require a valid CSRF token. Requests without a valid token will be rejected with HTTP 403 Forbidden.
- **Client-side impact**: The client (frontend) must extract and include the CSRF token in all state-changing requests. For JSON-based AJAX requests, this typically means adding the token to the `X-CSRF-TOKEN` request header or as a request parameter named `_csrf`.
- **Token storage**: Spring Security uses `HttpSessionCsrfTokenRepository` by default, which stores the token in the HTTP session. The token is generated once per session and remains constant across requests within that session.
- **No other security contract changes**: Authorization checks and authentication remain unchanged; only the CSRF validation layer is re-enabled.
