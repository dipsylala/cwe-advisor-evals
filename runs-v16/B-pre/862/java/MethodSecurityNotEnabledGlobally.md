## Verdict

Exploitable. The `deleteUserAccount` method performs a sensitive action (deleting a user account) but lacks proper authorization enforcement at two levels:

1. **Global configuration gap**: Method-level security is not enabled, rendering the `@PreAuthorize` annotation inert.
2. **Resource-level gap**: The authorization check validates only the caller's role (ADMIN) but does not verify the caller has permission to delete the *specific* user account, allowing privilege escalation.

## Source

The `userId` parameter in the `deleteUserAccount(long userId)` method, supplied by an authenticated caller and passed directly to the repository deletion method without ownership validation.

## Fix

### Create a Spring Security configuration class (SecurityConfig.java)

```java
package com.example.accounts;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    // This configuration enables Spring Security method-level authorization
    // and processes @PreAuthorize/@PostAuthorize annotations at runtime.
}
```

### Update UserAccountService with resource-level authorization

**Vulnerable code:**

```java
@PreAuthorize("hasRole('ADMIN')")
public void deleteUserAccount(long userId) {
    // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    userAccountRepository.deleteById(userId);
}
```

**Fixed code:**

```java
@PreAuthorize("@userAccountSecurity.canDeleteAccount(#userId, authentication.name)")
public void deleteUserAccount(long userId) {
    userAccountRepository.deleteById(userId);
}
```

### Create a security bean for authorization logic (UserAccountSecurity.java)

```java
package com.example.accounts;

import org.springframework.stereotype.Component;

@Component("userAccountSecurity")
public class UserAccountSecurity {

    private final UserAccountRepository userAccountRepository;

    public UserAccountSecurity(UserAccountRepository userAccountRepository) {
        this.userAccountRepository = userAccountRepository;
    }

    public boolean canDeleteAccount(long userId, String authenticatedUsername) {
        // Load the target account
        UserAccount targetAccount = userAccountRepository.findById(userId)
                .orElse(null);
        if (targetAccount == null) {
            return false; // Account does not exist
        }

        // Verify the authenticated user owns or has permission to delete this account
        // This example checks if the account belongs to the authenticated user or the user is the account's manager
        return targetAccount.getOwner().equals(authenticatedUsername) || 
               targetAccount.getManagerId().equals(authenticatedUsername);
    }
}
```

## Explanation

The vulnerability arises from two missing authorization mechanisms. First, Spring Security method-level authorization is not enabled globally, so the existing `@PreAuthorize` annotation is ignored by the runtime and never enforced. Second, the authorization check validates only role membership (ADMIN) without verifying resource-level access (ownership or assignment). This allows any ADMIN user to delete any user account by simply changing the `userId` parameter, violating the principle of least privilege.

The fix adds a `SecurityConfig` class with `@EnableMethodSecurity` to activate Spring Security's method-level advice. The `@PreAuthorize` annotation now delegates to a security bean (`UserAccountSecurity`) that loads the target account from the repository and verifies the authenticated user has ownership or management rights to it. The SpEL expression `@userAccountSecurity.canDeleteAccount(#userId, authentication.name)` extracts the user ID from the method parameter and the authenticated username from the security context, passing both to the bean for evaluation. If the authorization bean returns false, `AccessDeniedException` is raised and `ExceptionTranslationFilter` translates it to a 403 Forbidden response.

## Behaviour changes

- **New dependency on UserAccountSecurity bean**: The method now requires a security bean to evaluate ownership. The bean must load the account and implement the ownership logic; the exact ownership model (single owner, manager assignment, role-based inheritance) is application-specific and should match your authorization domain model.
- **Authorization denial behavior**: Calls by ADMIN users lacking ownership of the target account now raise `AccessDeniedException` (translated to 403 by Spring Security filters) instead of silently succeeding. Calls by non-authenticated users are sent to the authentication entry point. Calls by non-ADMIN authenticated users are denied. Calls with a non-existent `userId` return 403 (not 404) to avoid leaking account existence; if account existence is not sensitive, modify the bean to return 404 for missing accounts.
- **No change to deletion semantics**: The underlying `deleteById` call, return behavior, and exception handling remain unchanged. The fix adds authorization only.
