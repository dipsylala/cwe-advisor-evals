## Verdict

Exploitable. The `@PreAuthorize` annotations are present on the service methods but have no effect because Spring's method-level security framework is not enabled globally. Any caller can invoke `deleteUserAccount()` regardless of role, bypassing the intended authorization check.

## Source

The `userId` parameter to `deleteUserAccount(long userId)`, supplied by an HTTP request handler calling this service method. The caller's identity and role are available to Spring Security, but the authorization framework does not evaluate the `@PreAuthorize` constraint.

## Fix

The vulnerable code has the correct authorization intent in the service layer:

```java
@PreAuthorize("hasRole('ADMIN')")
public void deleteUserAccount(long userId) {
    userAccountRepository.deleteById(userId);
}
```

The fix is not in the service code, but in the Spring Security configuration. The application must enable method-level security. Add a Spring Security configuration class with the `@EnableMethodSecurity` annotation:

```java
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {
    // SecurityFilterChain and other beans defined here
}
```

If the application uses the deprecated `@EnableGlobalMethodSecurity` (Spring Security 5.5 and earlier), replace it with `@EnableMethodSecurity`, which is the modern standard since Spring Security 5.6.

## Explanation

Without the `@EnableMethodSecurity` annotation on a Spring Security configuration class, method-level authorization annotations like `@PreAuthorize` and `@Secured` are parsed but not enforced at runtime. The Spring AOP proxy that intercepts method calls to check authorization is never registered, so the method executes without any authorization decision. Adding `@EnableMethodSecurity` activates the authorization interceptor, causing Spring to evaluate each `@PreAuthorize` expression before the method runs. In this case, calls lacking the `ROLE_ADMIN` authority will raise `AccessDeniedException` before `deleteUserAccount()` executes.

## Behaviour changes

None in the service code. The fix requires only adding a configuration annotation in a separate configuration class. The runtime behavior changes: `deleteUserAccount()` calls now enforce the `hasRole('ADMIN')` check and raise `AccessDeniedException` for unauthorized callers, rather than silently allowing any call through. This is the intended correction, not a regression.
