## Verdict

Confirmed CWE-862 vulnerability. The `deleteUserAccount` method declares authorization via `@PreAuthorize` but lacks explicit runtime verification that the user is authenticated and holds the required ADMIN role before executing the sensitive repository operation.

## Source

**File:** `UserAccountService.java`  
**Line:** 18  
**Vulnerable Code:**
```java
@PreAuthorize("hasRole('ADMIN')")
public void deleteUserAccount(long userId) {
    userAccountRepository.deleteById(userId);  // Line 18 - no explicit authorization check
}
```

The vulnerability is that while the method declaration includes `@PreAuthorize`, this annotation alone does not guarantee runtime authorization enforcement without proper Spring Security configuration. The actual delete operation proceeds without explicit verification that the caller is authenticated and possesses the ADMIN role.

## Fix

### File: UserAccountService.java

```java
package com.example.accounts;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class UserAccountService {

    private final UserAccountRepository userAccountRepository;

    public UserAccountService(UserAccountRepository userAccountRepository) {
        this.userAccountRepository = userAccountRepository;
    }

    @PreAuthorize("hasRole('ADMIN')")
    public void deleteUserAccount(long userId) {
        // Explicit authorization verification
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            throw new AccessDeniedException("User not authenticated");
        }
        
        boolean hasAdminRole = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(authority -> authority.equals("ROLE_ADMIN"));
        
        if (!hasAdminRole) {
            throw new AccessDeniedException("User does not have ADMIN role");
        }
        
        userAccountRepository.deleteById(userId);
    }

    @PreAuthorize("hasRole('ADMIN')")
    public void suspendUserAccount(long userId) {
        UserAccount account = userAccountRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown user " + userId));
        account.setSuspended(true);
        userAccountRepository.save(account);
    }
}
```

## Explanation

The fix implements defense-in-depth authorization by combining declarative and explicit verification:

1. **Declarative Authorization:** The `@PreAuthorize("hasRole('ADMIN')")` annotation remains as the first line of defense, requiring Spring Security's method-level security to be enabled.

2. **Explicit Runtime Verification:** Inside the method body, before executing the sensitive operation, the code explicitly:
   - Retrieves the current `Authentication` from `SecurityContextHolder`
   - Verifies the user is authenticated
   - Checks that the user's authorities include the `ROLE_ADMIN` role
   - Throws `AccessDeniedException` if either check fails

3. **Defense Layers:** This dual approach ensures authorization is enforced even if the declarative annotation is misconfigured or Spring Security's method interception is not properly enabled. The explicit checks act as a safety net to prevent unauthorized account deletion.

E:/Github/cwe-advisor/evals/runs-v17/A/862/java/MethodSecurityNotEnabledGlobally.md
