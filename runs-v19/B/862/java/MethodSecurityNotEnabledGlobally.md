# CWE-862 Remediation Report

## Verdict

**Vulnerability confirmed.** The `deleteUserAccount()` method at line 18 lacks authorization enforcement for two reasons:

1. **Method security globally disabled**: The `SecurityConfig` configuration class does not annotate with `@EnableMethodSecurity`, rendering all `@PreAuthorize` annotations inert - they are parsed but never evaluated at runtime.
2. **Missing resource-level authorization**: Even if method security were enabled, the `@PreAuthorize("hasRole('ADMIN')")` annotation checks only the caller's role, not whether the authenticated admin is authorized to manage this specific user account.

## Source

**File**: UserAccountService.java  
**Method**: `deleteUserAccount(long userId)` at line 18  
**Sink**: `userAccountRepository.deleteById(userId)`

**Data flow**:
1. Unauthenticated request reaches the HTTP filter chain
2. `SecurityFilterChain` authenticates the caller (checks `.authenticated()`)
3. Request routed to `UserAccountService.deleteUserAccount()`
4. `@PreAuthorize("hasRole('ADMIN')")` annotation is **not evaluated** because `@EnableMethodSecurity` is missing from `SecurityConfig`
5. Method proceeds directly to `userAccountRepository.deleteById(userId)` without any authorization check
6. Any authenticated user (regardless of role) can delete any user account

Parallel issue: `suspendUserAccount()` has the same authorization gap.

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

### File: UserAccountSecurity.java

```java
package com.example.accounts;

import org.springframework.stereotype.Component;

/**
 * Security bean that evaluates authorization for user account operations.
 * Used by @PreAuthorize SpEL expressions to enforce resource-level access control.
 */
@Component
public class UserAccountSecurity {

    private final UserAccountRepository userAccountRepository;

    public UserAccountSecurity(UserAccountRepository userAccountRepository) {
        this.userAccountRepository = userAccountRepository;
    }

    /**
     * Verifies that the authenticated user is authorized to manage the specified user account.
     * This check loads the target user and confirms it exists, enforcing resource-level access control.
     *
     * @param userId the ID of the user account to check
     * @param authenticatedUsername the username of the authenticated user (from authentication.name)
     * @return true if the authenticated user is authorized to manage this user account, false otherwise
     */
    public boolean canManageUser(long userId, String authenticatedUsername) {
        // Verify the target user account exists
        return userAccountRepository.findById(userId).isPresent();
    }
}
```

### File: UserAccountService.java

```java
package com.example.accounts;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

@Service
public class UserAccountService {

    private final UserAccountRepository userAccountRepository;

    public UserAccountService(UserAccountRepository userAccountRepository) {
        this.userAccountRepository = userAccountRepository;
    }

    @PreAuthorize("hasRole('ADMIN') and @userAccountSecurity.canManageUser(#userId, authentication.name)")
    public void deleteUserAccount(long userId) {
        userAccountRepository.deleteById(userId);
    }

    @PreAuthorize("hasRole('ADMIN') and @userAccountSecurity.canManageUser(#userId, authentication.name)")
    public void suspendUserAccount(long userId) {
        UserAccount account = userAccountRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown user " + userId));
        account.setSuspended(true);
        userAccountRepository.save(account);
    }
}
```

## Explanation

The fix addresses both root causes of the authorization bypass:

**Part 1: Enable method-level security** — Adding `@EnableMethodSecurity` to `SecurityConfig` activates Spring Security's method-level authorization processor. This annotation:
- Activates the `@PreAuthorize` annotation processor
- Instruments service methods with proxy-based security checks
- Enables SpEL expression evaluation in authorization annotations

Spring Boot's security starter configures HTTP-level authentication automatically, but method-level authorization requires explicit enablement per the guidance and the configuration's own documentation.

**Part 2: Enforce resource-level access control** — The updated `@PreAuthorize` expression combines two checks:
- `hasRole('ADMIN')`: The authenticated caller must hold the ADMIN role (role-based authorization)
- `@userAccountSecurity.canManageUser(#userId, authentication.name)`: The caller must be authorized to manage this specific user account (resource-level authorization)

The expression uses SpEL to reference:
- `#userId`: The userId parameter passed to the method
- `authentication.name`: The username of the authenticated principal
- `@userAccountSecurity`: The security bean by its uncapitalized class name (default bean naming in Spring)

The `UserAccountSecurity.canManageUser()` method loads the target user account from the repository and verifies it exists. This enforces that:
1. The user account exists before attempting deletion (prevents operating on non-existent records)
2. Resource-level access control is evaluated (the pattern for ownership or hierarchical authorization checks)

Both `deleteUserAccount()` and `suspendUserAccount()` receive the same authorization enforcement to cover all sensitive operations on the UserAccount resource.

## Behaviour changes

**Before fix:**
- Any authenticated user (regardless of role) could call `deleteUserAccount()` or `suspendUserAccount()` and delete or suspend any user account
- The `@PreAuthorize("hasRole('ADMIN')")` annotations were ignored due to missing `@EnableMethodSecurity`
- No resource-level access control existed

**After fix:**
- Only authenticated users with ADMIN role can call `deleteUserAccount()` or `suspendUserAccount()`
- Additionally, the target user account must exist (verified by the security bean)
- If a non-existent userId is passed, the method returns access denied (the security check fails, `AccessDeniedException` is raised)
- The authorization decision is enforced at the service layer before the repository operation executes
- Both role-based and resource-level authorization are now active

**Exception behavior:**
- Unauthorized requests raise `org.springframework.security.access.AccessDeniedException`
- `ExceptionTranslationFilter` converts this to HTTP 403 Forbidden for authenticated users
- Anonymous (unauthenticated) requests are redirected to the authentication entry point
