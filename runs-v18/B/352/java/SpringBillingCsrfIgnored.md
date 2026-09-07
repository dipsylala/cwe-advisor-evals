## Verdict

CONFIRMED - CWE-352 Cross-Site Request Forgery (CSRF)

The SecurityConfig.java explicitly disables CSRF protection for the `/api/billing/**` route pattern using `csrf().ignoringRequestMatchers()`, leaving the state-changing PATCH endpoint at `/api/billing/card` unprotected against CSRF attacks.

## Source

**File**: SecurityConfig.java  
**Line**: 12  
**Vulnerable code**: `.csrf(csrf -> csrf.ignoringRequestMatchers("/api/billing/**"))`

The call to `ignoringRequestMatchers()` exempts all routes matching `/api/billing/**` from CSRF token validation. The BillingController.updateCard() method at `/api/billing/card` is a PATCH endpoint that modifies sensitive billing information (customer card tokens) - a classic state-changing operation that must be protected against CSRF.

**Call chain**:
1. SecurityConfig.apiSecurity() configures Spring Security's HttpSecurity
2. `.csrf()` builds a CSRF configuration object
3. `.ignoringRequestMatchers("/api/billing/**")` exempts the billing routes from CSRF protection
4. BillingController.updateCard() receives unvalidated PATCH requests

## Fix

### File: SecurityConfig.java

```java
package cases.csrf;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

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

The vulnerability is closed by removing the `.csrf(csrf -> csrf.ignoringRequestMatchers("/api/billing/**"))` configuration entirely. Spring Security enables CSRF protection by default - when no explicit CSRF configuration is provided, the framework automatically validates synchronizer tokens for all state-changing requests (POST, PUT, DELETE, PATCH).

By removing the exemption, all requests to `/api/billing/**` are now subject to CSRF token validation. The framework will reject any PATCH request to `/api/billing/card` that does not include a valid CSRF token in either:
- A hidden form field named `_csrf` (for traditional form submissions)
- The `X-CSRF-TOKEN` or `X-XSRF-TOKEN` request header (for AJAX/REST API calls)

The framework uses Spring Security's default token store (HttpSessionCsrfTokenRepository), which generates tokens cryptographically secure (UUID.randomUUID()) and compares them in constant time via MessageDigest.isEqual(), preventing both timing attacks and token prediction.

## Behaviour changes

**For legitimate clients**: REST API clients must now include a valid CSRF token when sending PATCH requests to `/api/billing/card`. Clients can obtain the token from a separate token endpoint or from response headers if configured to expose it. The token must be included in the `X-CSRF-TOKEN` header.

**For attack scenarios**: Cross-site requests from malicious domains will now fail with HTTP 403 Forbidden. Attackers cannot forge CSRF tokens because tokens are server-generated, session-bound, and validated in constant time.

**For authenticated users**: Users remain authenticated to the service; CSRF protection does not affect the authentication mechanism. It only requires proof that requests originate from this application, not from cross-site attackers.
