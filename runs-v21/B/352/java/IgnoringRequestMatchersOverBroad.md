## Verdict

CONFIRMED. The CSRF protection is disabled for a pattern broader than necessary. The `.csrf().ignoringRequestMatchers("/api/**")` exempts all API routes from CSRF protection, including authenticated state-changing endpoints that should be protected. The exemption should be narrowed to only the webhook endpoint that cannot present a CSRF token (`/api/webhooks/**`).

## Source

The source of the CSRF vulnerability is an attacker in a browser context with an active session to the application. The attacker crafts a malicious page or request that induces an authenticated user to make an unwanted state-changing request (POST, PUT, DELETE) to any `/api/**` endpoint without a valid CSRF token.

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
            .csrf(csrf -> csrf.ignoringRequestMatchers("/api/webhooks/**"))
            .build();
    }
}
```

## Explanation

The vulnerability arises from an over-broad CSRF protection exemption. The original code disables CSRF validation for all routes matching `/api/**`, which includes authenticated state-changing endpoints that must be protected. The fix narrows the exemption to only `/api/webhooks/**`, the endpoint that genuinely requires exemption because third-party payment providers cannot present a CSRF token. All other API routes now enforce CSRF token validation, preventing attackers from executing state-changing actions on behalf of authenticated users. The exemption pattern now aligns with the intent expressed in the code comments: only webhook callbacks are exempt, while all other authenticated API routes retain full CSRF protection through Spring Security's token-based verification.

## Behaviour changes

- **CSRF protection enabled**: All authenticated API routes matching `/api/**` except `/api/webhooks/**` now require a valid CSRF token in state-changing requests (POST, PUT, DELETE, PATCH). Requests without valid tokens will receive a 403 Forbidden response.
- **Webhook callbacks unchanged**: Third-party payment providers can continue to POST callbacks to `/api/webhooks/**` without presenting a CSRF token, preserving integration with external payment systems.
- **No client changes required**: The narrow exemption maintains the same user experience for legitimate clients - only the scope of the protection has been corrected.
