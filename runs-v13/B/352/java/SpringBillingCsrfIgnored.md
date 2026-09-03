## Verdict

exploitable

## Source

Authenticated user with an active session accessing the application.

## Fix

**Vulnerable code** (SecurityConfig.java, line 12):

```java
public class SecurityConfig {
    @Bean
    SecurityFilterChain apiSecurity(HttpSecurity http) throws Exception {
        return http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .csrf(csrf -> csrf.ignoringRequestMatchers("/api/billing/**"))  // CSRF protection disabled
            .build();
    }
}
```

**Fixed code**:

```java
public class SecurityConfig {
    @Bean
    SecurityFilterChain apiSecurity(HttpSecurity http) throws Exception {
        return http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            // CSRF protection enabled for all endpoints (default behavior)
            .build();
    }
}
```

**Client-side change for AJAX requests** (send CSRF token in X-CSRF-TOKEN header):

```javascript
// When making PATCH request to /api/billing/card:
fetch('/api/billing/card', {
    method: 'PATCH',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRF-TOKEN': document.querySelector('meta[name="_csrf"]').getAttribute('content')
    },
    body: JSON.stringify({ customerId: '123', token: 'card_token' })
});
```

And add a meta tag in the HTML template to expose the CSRF token to JavaScript:

```html
<meta name="_csrf" content="${_csrf.token}"/>
```

## Explanation

The vulnerability exists because CSRF protection is explicitly disabled for the `/api/billing/**` path using `csrf(csrf -> csrf.ignoringRequestMatchers("/api/billing/**"))`. This allows the `@PatchMapping("/api/billing/card")` endpoint—a state-changing operation that modifies sensitive billing data—to be executed without verifying the request origin. Removing the `ignoringRequestMatchers()` configuration re-enables Spring Security's default CSRF protection, which validates tokens on all state-changing requests (PATCH, POST, PUT, DELETE). Since this is a REST endpoint accessed via AJAX, the client must send the CSRF token in the `X-CSRF-TOKEN` header rather than as a form parameter. Spring Security's `CsrfFilter` validates the submitted token against the server-side session-bound token in constant time before processing the request, preventing attackers from forging valid billing updates.

## Behaviour changes

none
