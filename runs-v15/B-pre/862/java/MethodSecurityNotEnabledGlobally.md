## Verdict

Exploitable. An authenticated user without ADMIN role can delete any user account through the `/api/admin/users/{userId}` endpoint.

## Source

HTTP DELETE request to `/api/admin/users/{userId}` from an authenticated user lacking the ADMIN role.

## Fix

**Vulnerable Code:**

File: `SecurityConfig.java` (lines 13-24)
```java
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .anyRequest().authenticated()
            );
        return http.build();
    }
}
```

File: `UserAccountService.java` (lines 15-19) - has authorization annotation but it is unenforced
```java
@PreAuthorize("hasRole('ADMIN')")
public void deleteUserAccount(long userId) {
    // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    userAccountRepository.deleteById(userId);
}
```

**Fixed Code:**

File: `SecurityConfig.java` - add `@EnableMethodSecurity` annotation
```java
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .anyRequest().authenticated()
            );
        return http.build();
    }
}
```

The `UserAccountService.java` method already carries the correct `@PreAuthorize("hasRole('ADMIN')")` annotation and requires no changes once method security is enabled.

## Explanation

Spring Boot's security starter enables HTTP authentication by default through the `SecurityFilterChain`, but does not activate method-level authorization annotations (`@PreAuthorize`, `@Secured`, `@PostAuthorize`) on its own. The `@EnableMethodSecurity` annotation (introduced in Spring Security 5.6+) activates the proxy-based enforcement of these annotations. Without it, all `@PreAuthorize` annotations in the service layer are evaluated by nothing and have no effect, leaving the authorization decision to the HTTP-level rules alone. Since the `SecurityFilterChain` in this configuration only requires authentication (`.anyRequest().authenticated()`), any logged-in user - regardless of role - can call the protected methods. Adding `@EnableMethodSecurity` to the `@Configuration` class instructs Spring to intercept method calls and enforce the role checks expressed in `@PreAuthorize` annotations before the method executes, raising `AccessDeniedException` when an unauthorized user attempts to call it.

## Behaviour changes

None. Adding `@EnableMethodSecurity` enables enforcement of the authorization annotations that are already present. The method signature, return type, and exception behavior remain unchanged - unauthorized access will now raise `AccessDeniedException` (which Spring's `ExceptionTranslationFilter` translates to HTTP 403 for authenticated users), whereas previously the method would execute normally for any authenticated user.
