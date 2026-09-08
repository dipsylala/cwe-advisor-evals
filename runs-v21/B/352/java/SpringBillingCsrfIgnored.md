## Verdict

Exploitable. The SecurityConfig explicitly disables CSRF protection for the `/api/billing/**` endpoint pattern, which includes the `@PatchMapping("/api/billing/card")` endpoint that mutates sensitive billing data (card token). An attacker can force an authenticated user to submit a malicious PATCH request to update their billing card without a valid CSRF token by embedding the request in an external website.

## Source

The vulnerability originates from the client request to the `@PatchMapping("/api/billing/card")` endpoint in BillingController, which updates billing card information via the BillingService.

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

The fix removes the `.csrf(csrf -> csrf.ignoringRequestMatchers("/api/billing/**"))` configuration that explicitly disabled CSRF protection for the billing endpoints. By removing this exclusion, the SecurityFilterChain now uses Spring Security's default CSRF protection, which is enabled by default in Spring Boot. The CSRF filter will now require valid CSRF tokens on all state-changing HTTP methods (POST, PUT, DELETE, PATCH) to the `/api/billing/card` endpoint. Clients must include the CSRF token in the request header (e.g., `X-CSRF-TOKEN` for AJAX requests) or as a form parameter (`_csrf`) for form submissions. This prevents attackers from forging requests on behalf of authenticated users, as they cannot obtain the server-generated CSRF token bound to the victim's session.

## Behaviour changes

None. Removing the CSRF exclusion restores Spring Security's default CSRF token validation for state-changing operations. The `authorizeHttpRequests()` configuration requiring authentication remains unchanged. The SecurityFilterChain still requires authentication for all requests; the only change is that state-changing requests to `/api/billing/**` now also require a valid CSRF token. Clients calling the PATCH endpoint will need to include the CSRF token, but this is the correct security behavior and does not introduce any additional breaking changes beyond what is necessary to eliminate the weakness.
