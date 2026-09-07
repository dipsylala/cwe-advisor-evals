## Verdict
CWE-352 Cross-Site Request Forgery — Confirmed. The CSRF protection exemption is overly broad, disabling token validation for all `/api/**` routes instead of only the intended webhook endpoint.

## Source
The vulnerability is in SecurityConfig.java, line 24:
```java
.csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"))
```

The exemption pattern `/api/**` disables CSRF protection for every route under `/api/`, including authenticated state-changing operations that must be protected. The comments document that only `/api/webhooks/**` (third-party payment callbacks) should be exempted, but the code grants exemption to the entire `/api/` namespace.

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
The fix narrows the CSRF exemption from `/api/**` to `/api/webhooks/**`, matching the documented intent and the authorization rule on line 21 that already distinguishes webhooks from the rest of the API.

Third-party webhook endpoints that cannot provide CSRF tokens are now the only routes exempt from CSRF validation. All other state-changing API routes retain full CSRF protection against forged requests.

This addresses the vulnerability where an attacker could exploit the overly broad exemption to forge requests against protected endpoints that should require valid CSRF tokens.
