## Verdict

exploitable

- cwe_id: CWE-352 (Cross-Site Request Forgery)
- location: `SecurityConfig.java`, line 24 (sink: `csrf.ignoringRequestMatchers("/api/**")` inside the `.csrf(...)` customizer of the `apiSecurity` `SecurityFilterChain` bean)
- confidence: high

## Source

The source is any authenticated cross-origin request an attacker's page can induce the victim's browser to send - a form auto-submit or fetch to any `/api/**` endpoint other than `/api/webhooks/**`. Spring Security's `CsrfFilter` is the control that is supposed to intercept non-safe methods (POST/PUT/DELETE/PATCH) on those endpoints; `ignoringRequestMatchers("/api/**")` is a filter-chain-level exclusion, so this is a single-file configuration finding rather than a multi-hop taint flow - the exclusion pattern itself is the vulnerable value and the `CsrfFilter` bypass is the sink.

- `authorizeHttpRequests` permits `/api/webhooks/**` unauthenticated and requires authentication for `anyRequest()` - so every other `/api/**` route is authenticated and, per the file's own comment, state-changing.
- `.csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"))` excludes the entire `/api/**` tree from CSRF validation, not just `/api/webhooks/**`. The `**` wildcard in the exclusion matcher is broader than the wildcard in the permit rule one line above it, so every authenticated, state-changing `/api/**` endpoint (e.g. `/api/account/close`, `/api/orders`) is reachable with no `_csrf` token check.
- The file's own comment states the intended scope explicitly ("Every other /api/** route ... must keep CSRF protection - the pattern below is broader than that intent"), confirming this is a genuine over-broad exclusion rather than a deliberate, reviewed design choice.

Sink contract (`ignoringRequestMatchers(RequestMatcher... matchers)` on `CsrfConfigurer`):
- **Returns**: the same `CsrfConfigurer`, for chaining; the matchers are stored and consulted by `CsrfFilter` to decide which requests skip CSRF validation.
- **Discards**: nothing produced - the call has no return value consumed beyond chaining.
- **Arguments left implicit**: none beyond the matcher pattern itself; there is no separate enable/disable flag being touched here - CSRF stays enabled for everything not matched.
- **Failure behaviour**: not applicable - a request matching the pattern silently skips CSRF validation (no exception, no logged warning); a request not matching it that lacks a valid token gets `403 Forbidden` from `CsrfFilter`.

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
    // keep CSRF protection.
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

The `ignoringRequestMatchers` pattern was narrowed from `/api/**` to `/api/webhooks/**`, matching exactly the scope the file's own comment describes: only the unauthenticated third-party webhook callbacks - which cannot carry a session-bound CSRF token - are excluded from `CsrfFilter`. Every other `/api/**` endpoint, all of which are authenticated per the `authorizeHttpRequests` block and state-changing per the comment, now falls back to Spring Security's default-enabled CSRF protection and must present a valid `_csrf` token on POST/PUT/DELETE/PATCH requests, closing the forgery window. No other configuration changed: authentication rules, HTTP methods, and the webhook exemption itself are unchanged - only the exclusion matcher's scope was corrected to match the stated intent.

## Behaviour changes

- Every `/api/**` route other than `/api/webhooks/**` (e.g. an account or orders endpoint) now requires a valid `_csrf` token on state-changing requests; any existing authenticated client calling those endpoints without a CSRF token will start receiving `403 Forbidden`. This is the intended effect of the fix, not a side effect - the code comment states these routes were meant to keep CSRF protection all along, so a compliant client already includes the token or needs to be updated to do so.
- `/api/webhooks/**` behaviour is unchanged: still `permitAll()` for authorization and still excluded from CSRF validation, since third-party payment callbacks cannot present a session-bound token.
- No other difference: authentication rules, HTTP methods, bean structure, and imports are all identical to the original file.
- Removed the trailing comment clause "- the pattern below is broader than that intent" since the pattern no longer is; the rest of the comment (the rationale for excluding webhooks) is preserved verbatim.

## Verification

Ran `javac` (JDK 26, present on the environment) against the fixed file in isolation, with no Spring dependencies on the classpath. All 10 reported errors are `package ... does not exist` / `cannot find symbol` for Spring/Spring Security types, which is expected with no classpath configured - no syntax errors were reported, confirming the file parses as valid Java. Full semantic compilation against the real Spring Security jars was not run since the case directory's build configuration was not available to this check; the only change made (narrowing a string literal argument to an existing method call) does not alter any signature, import, or type used elsewhere in the file.

## Assumptions

- No CI/build files (pom.xml/build.gradle) were present in the case directory to compile against the real Spring Security classpath; verification relied on syntax-only `javac` parsing plus manual review, per the note above.
