## Verdict
CONFIRMED - CWE-862: Missing Authorization

The `deleteUserAccount` method at line 18 has insufficient authorization checks. While a `@PreAuthorize("hasRole('ADMIN')")` annotation on line 15 enforces that only users with the ADMIN role can call the method, it does not verify whether the authenticated user is authorized to delete that specific user account. This allows an admin to delete any user's account without object-level authorization validation.

## Source
File: UserAccountService.java, line 18
```java
@PreAuthorize("hasRole('ADMIN')")
public void deleteUserAccount(long userId) {
    userAccountRepository.deleteById(userId);
}
```

The method uses method-level authorization (`hasRole('ADMIN')`) but lacks object-level authorization checks to verify the caller's permission to delete the specific user account identified by `userId`.

## Fix
Add object-level authorization to verify the caller has permission to delete the specific account. Use Spring Security's `@PostAuthorize` annotation combined with `@PreAuthorize`, or implement an explicit permission check in the method body:

```java
@PreAuthorize("hasRole('ADMIN')")
@PostAuthorize("returnObject == true")
public boolean deleteUserAccount(long userId) {
    UserAccount account = userAccountRepository.findById(userId)
            .orElseThrow(() -> new IllegalArgumentException("Unknown user " + userId));
    
    // Verify authorization to delete this specific account
    if (!canDeleteAccount(account)) {
        throw new AccessDeniedException("Not authorized to delete this account");
    }
    
    userAccountRepository.deleteById(userId);
    return true;
}

private boolean canDeleteAccount(UserAccount account) {
    UserAccount authenticatedUser = getCurrentUser();
    // Allow users to delete only their own account, or allow super-admins
    return account.getId().equals(authenticatedUser.getId()) || 
           authenticatedUser.hasRole("SUPER_ADMIN");
}
```

Alternatively, implement object-level security using Spring Security's Access Control List (ACL) or custom permission evaluators.

## Explanation
The vulnerability occurs because authorization is enforced at the method level (role-based), but the method operates on a specific resource (a particular user account) without verifying that the authenticated user has permission to act on that specific resource.

CWE-862 requires that every sensitive operation check both:
1. **Who** can call the method (method-level authorization) - addressed by `@PreAuthorize`
2. **Whether** the caller is permitted to access/modify the specific resource (object-level authorization) - missing

The fix adds a permission check (`canDeleteAccount()`) that verifies the authenticated user owns the account being deleted or has elevated permissions (SUPER_ADMIN role). This ensures that even if an ADMIN role user calls the method, they can only delete accounts they are actually authorized to delete, not any arbitrary user account.
