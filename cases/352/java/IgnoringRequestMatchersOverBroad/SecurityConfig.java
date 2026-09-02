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
            .csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"))
            .build();
    }
}
