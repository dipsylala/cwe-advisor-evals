## Verdict
The CSRF protection is disabled too broadly. The pattern `/api/**` excludes all API endpoints from CSRF validation, when only the webhook endpoint `/api/webhooks/**` legitimately requires this exception. Other authenticated state-changing API routes remain vulnerable.

## Source
Line 24 in SecurityConfig.java uses an overly broad request matcher pattern in the `csrf().ignoringRequestMatchers()` call:
```java
.csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"))
```

The intent is documented in the code comment: only `/api/webhooks/**` (third-party payment callbacks) should bypass CSRF protection. All other `/api/**` routes are state-changing and must retain CSRF validation.

## Fix
### File: SecurityConfig.java
```java
package cases.csrf;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // Third-party payment providers POST callbacks to /api/webhooks/** and cannot
    // present a CSRF token, so that path must sit outside the CSRF filter.
    // Every other /api/** route is authenticated and state-changing, and must
    // keep CSRF protection - the pattern below is broader than that intent.
    @Bean
    SecurityFilterChain apiSecurity(HttpSecurity http) throws Exception {
        return http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/webhooks/**").permitAll()
                .anyRequest().authenticated())
            // SAST FINDING: CWE-352 (Cross-Site Request Forgery) reported here. Sink is the next statement.
            .csrf(csrf -> csrf.ignoringRequestMatchers("/api/webhooks/**"))
            .build();
    }
}
```

## Explanation
The vulnerability occurs because the request matcher pattern in `csrf().ignoringRequestMatchers()` is overly broad. By using `/api/**`, the configuration disables CSRF token validation for the entire API namespace, which contradicts the documented intent to exempt only the webhook endpoint.

The fix narrows the pattern from `/api/**` to `/api/webhooks/**`, ensuring that:
1. The webhook endpoint at `/api/webhooks/**` remains unprotected (required because third-party providers cannot provide CSRF tokens)
2. All other API endpoints under `/api/**` retain CSRF protection and validate the presence and validity of CSRF tokens
3. The configuration now matches the documented security requirement

This prevents attackers from exploiting CSRF vulnerabilities in authenticated state-changing endpoints like `/api/orders/**`, `/api/users/**`, or similar protected resources that handle sensitive operations.
