## Verdict

Authorization check present but not enforced. `@PreAuthorize` annotations in `UserAccountService` are ignored because Spring method-level security is not globally enabled in the configuration. This allows any authenticated user to perform admin-only operations. CWE-862 confirmed.

## Source

**File**: `UserAccountService.java`, lines 15-18

**Context**:
```java
@PreAuthorize("hasRole('ADMIN')")
public void deleteUserAccount(long userId) {
    // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    userAccountRepository.deleteById(userId);
}
```

**Call chain**:
1. `UserAccountController.deleteUser()` (line 18) calls `userAccountService.deleteUserAccount(userId)`
2. `UserAccountService.deleteUserAccount()` (line 16) is annotated with `@PreAuthorize("hasRole('ADMIN')")` but this annotation is not enforced
3. `userAccountRepository.deleteById(userId)` (line 18) deletes the account without authorization

**Root cause**: `SecurityConfig.java` lacks `@EnableMethodSecurity` annotation. Spring Boot's security starter does not automatically activate method-level authorization, so all `@PreAuthorize` annotations are evaluated by nothing and have no effect.

## Fix

### File: SecurityConfig.java

```java
package com.example.accounts;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

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

## Explanation

Added `@EnableMethodSecurity` annotation to the `SecurityConfig` class. This tells Spring Security to enable method-level authorization, which activates the evaluation of `@PreAuthorize` and `@Secured` annotations at runtime.

With this change:
- When `deleteUserAccount(long userId)` is called, Spring's method security interceptor evaluates `@PreAuthorize("hasRole('ADMIN')")`
- If the authenticated caller does not have the `ROLE_ADMIN` authority, an `AccessDeniedException` is thrown
- If the caller is not authenticated, the request is sent to the authentication entry point
- Only authenticated users with the ADMIN role can proceed to execute the method

The fix is minimal and focused: it adds only the missing configuration annotation required by Spring Security 5.6+ to enforce the authorization checks that were already declared via `@PreAuthorize` in the service layer.

## Behaviour changes

**Before**: Any authenticated user (regardless of role) can DELETE any user account by calling `DELETE /api/admin/users/{userId}` because `@PreAuthorize` is never evaluated.

**After**: Only authenticated users with the `ROLE_ADMIN` authority can DELETE user accounts. Requests from users lacking this role receive a 403 Forbidden response (for authenticated users) or are redirected to the authentication entry point (for unauthenticated requests).

**Impact**: The `suspendUserAccount()` method in the same service also has `@PreAuthorize("hasRole('ADMIN')")` and will now be properly enforced as well.

**Testing**: Call `DELETE /api/admin/users/1` as an authenticated user without ADMIN role and verify a 403 Forbidden response is returned instead of a successful deletion.
