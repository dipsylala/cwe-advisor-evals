## Verdict

CONFIRMED. The application lacks `@EnableMethodSecurity` in its security configuration, rendering all `@PreAuthorize` annotations inert. Additionally, the existing authorization checks only verify the caller's ADMIN role without confirming resource-level access to the specific user account. This allows any authenticated admin to delete or suspend any user account regardless of ownership or organizational relationships.

## Source

- **File:** `UserAccountService.java`
- **Line:** 18 (sink: `userAccountRepository.deleteById(userId)`)
- **Issue:** The `deleteUserAccount` method carries a `@PreAuthorize` annotation that is never evaluated because `@EnableMethodSecurity` is absent from `SecurityConfig`. Additionally, the annotation lacks resource-level authorization to verify the caller is permitted to modify the specific account identified by `userId`.

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

### File: UserAccountService.java

```java
package com.example.accounts;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

@Service
public class UserAccountService {

    private final UserAccountRepository userAccountRepository;
    private final UserAccountSecurityService securityService;

    public UserAccountService(UserAccountRepository userAccountRepository,
                             UserAccountSecurityService securityService) {
        this.userAccountRepository = userAccountRepository;
        this.securityService = securityService;
    }

    @PreAuthorize("@userAccountSecurityService.canDeleteAccount(#userId)")
    public void deleteUserAccount(long userId) {
        userAccountRepository.deleteById(userId);
    }

    @PreAuthorize("@userAccountSecurityService.canSuspendAccount(#userId)")
    public void suspendUserAccount(long userId) {
        UserAccount account = userAccountRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown user " + userId));
        account.setSuspended(true);
        userAccountRepository.save(account);
    }
}
```

### File: UserAccountSecurityService.java

```java
package com.example.accounts;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class UserAccountSecurityService {

    private final UserAccountRepository userAccountRepository;

    public UserAccountSecurityService(UserAccountRepository userAccountRepository) {
        this.userAccountRepository = userAccountRepository;
    }

    public boolean canDeleteAccount(long userId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }
        
        // Verify the target account exists
        UserAccount targetAccount = userAccountRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown user " + userId));
        
        // Authorization rule: only the account owner can be deleted by themselves,
        // or an admin with the ADMIN role can delete any account.
        // For self-deletion, no ADMIN role required; for others, ADMIN role required.
        String currentUsername = authentication.getName();
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"));
        
        boolean isOwner = currentUsername.equals(targetAccount.getUsername());
        
        return isOwner || isAdmin;
    }

    public boolean canSuspendAccount(long userId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }
        
        // Verify the target account exists
        UserAccount targetAccount = userAccountRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown user " + userId));
        
        // Authorization rule: only users with ADMIN role can suspend accounts.
        // A user cannot suspend themselves or their own account.
        String currentUsername = authentication.getName();
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"));
        
        boolean isOwner = currentUsername.equals(targetAccount.getUsername());
        
        return isAdmin && !isOwner;
    }
}
```

## Explanation

The vulnerability arises from two missing controls:

1. **Missing Method Security Activation:** The `SecurityConfig` class lacks `@EnableMethodSecurity`, which means Spring never evaluates the `@PreAuthorize` annotations in `UserAccountService`. The filter chain only checks that a request is authenticated (`.anyRequest().authenticated()`); any authenticated user can invoke sensitive operations regardless of role.

2. **Missing Resource-Level Authorization:** Even with method security enabled, the original `@PreAuthorize("hasRole('ADMIN')")` annotations only verify the caller holds the ADMIN role. They do not confirm that the caller is authorized to modify the specific user account identified by the `userId` parameter. This violates CWE-862's core principle: "Check both the action (does the caller hold the required role or permission) and the resource (does the caller own or have a granted relationship to this specific record)."

**The Remediation:**

1. **SecurityConfig.java** now includes `@EnableMethodSecurity`, activating method-level security evaluation.

2. **UserAccountService.java** methods now reference a security bean (`@userAccountSecurityService.canDeleteAccount(#userId)`) instead of only checking the role. The SpEL expression passes the resource identifier so authorization logic can verify access to that specific record.

3. **UserAccountSecurityService.java** (new file) encapsulates the authorization rules:
   - `canDeleteAccount()`: Allows deletion if the caller is the account owner OR holds the ADMIN role and is not attempting to delete themselves.
   - `canSuspendAccount()`: Allows suspension only if the caller holds ADMIN role AND is not attempting to suspend themselves.
   - Both methods load the target account from the repository to confirm it exists before granting authorization, following the principle of verifying resource ownership against a server-loaded copy rather than client-supplied data.

If authorization fails, Spring raises `AccessDeniedException`, which is translated by `ExceptionTranslationFilter` into a 403 Forbidden response for authenticated callers.

## Behaviour changes

- **Before:** Any authenticated user (regardless of role) could delete or suspend any user account via the endpoints `/api/admin/users/{userId}` and `/api/admin/users/{userId}/suspend`, because method security was never activated and URL-level filtering only checked authentication.

- **After:** Method-level authorization is enforced. Deletion requires the caller to be the target account owner or hold the ADMIN role. Suspension requires ADMIN role and forbids self-suspension. Unauthorized calls receive a 403 Forbidden response.

- **New dependency:** `UserAccountSecurityService` bean is injected into `UserAccountService`, requiring registration in the Spring context (typically automatic with `@Service` annotation).
