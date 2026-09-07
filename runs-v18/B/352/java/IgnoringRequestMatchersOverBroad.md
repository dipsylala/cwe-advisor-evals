## Verdict

Exploitable. The CSRF protection is disabled for all routes matching `/api/**`, which is overly broad compared to the stated intent in the code comments. Only `/api/webhooks/**` requires exemption for third-party payment callbacks; all other `/api/**` endpoints (such as account modifications, settings changes, transfers) remain unprotected against CSRF attacks and can be exploited by an attacker who crafts a malicious cross-site request targeting an authenticated user.

## Source

Framework configuration in the `SecurityConfig` bean that defines global CSRF protection settings. The developer's code comment indicates the intent to exempt only `/api/webhooks/**`, but the actual implementation exempts the broader `/api/**` pattern.

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

The vulnerability is caused by an overly broad CSRF protection exemption. The original `.csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"))` disables CSRF token validation for all routes starting with `/api/`, but the code comment explicitly documents that only `/api/webhooks/**` requires this exemption because third-party payment providers cannot include CSRF tokens in their callbacks. The fix narrows the exemption pattern to `/api/webhooks/**`, restoring CSRF protection to other state-changing endpoints under `/api/**`. This ensures that endpoints like account updates, settings modifications, and other authenticated operations maintain their CSRF defences while preserving the necessary exemption for webhook endpoints that cannot provide CSRF tokens.

## Behaviour changes

None. The fix only narrows the pattern from which routes are exempt from CSRF validation. The `ignoringRequestMatchers()` method's contract remains unchanged: routes matching the exemption skip CSRF validation, all other routes require it. Routes that previously relied on CSRF exemption were only the webhook routes anyway; other `/api/**` routes now properly enforce CSRF protection as intended.
