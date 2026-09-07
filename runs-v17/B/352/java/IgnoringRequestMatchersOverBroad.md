## Verdict

Confirmed. The CSRF exemption pattern is over-broad and leaves authenticated state-changing endpoints unprotected against CSRF attacks.

## Source

`SecurityConfig.java` line 24:
```java
.csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"))
```

The configuration disables CSRF token validation for all paths matching `/api/**`. The code comment explicitly documents the intent: only `/api/webhooks/**` should bypass CSRF protection because third-party webhooks cannot present tokens. All other `/api/**` routes are authenticated and state-changing, requiring CSRF protection.

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

The fix narrows the CSRF exemption from `/api/**` to `/api/webhooks/**`, matching the documented intent. This restores CSRF token validation on all authenticated state-changing endpoints under `/api/` except the webhook sink, which legitimately cannot present tokens because it receives requests from external payment providers. The exemption scope now aligns with the authorization configuration, which permits the webhook path unauthenticated while requiring authentication for all other requests.

## Behaviour changes

- **Protected endpoints gain CSRF validation**: All authenticated `/api/**` endpoints except `/api/webhooks/**` now require valid CSRF tokens in POST, PUT, PATCH, and DELETE requests. Requests without tokens are rejected with 403 Forbidden.
- **Webhook endpoint unchanged**: `/api/webhooks/**` continues to accept unauthenticated requests without tokens, as required for third-party integrations.
- **No impact on authorization**: The authorization rule remains unchanged; the webhook path is still permitted all, and other paths still require authentication.
