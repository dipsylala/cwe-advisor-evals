## Verdict

Exploitable

## Source

The `userId` parameter supplied to the `deleteUserAccount(long userId)` method from the HTTP request context, accessible to any authenticated user.

## Fix

**Vulnerable code** (line 15-18):
```java
@PreAuthorize("hasRole('ADMIN')")
public void deleteUserAccount(long userId) {
    // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    userAccountRepository.deleteById(userId);
}
```

**Fixed code**:
```java
@PreAuthorize("hasRole('ADMIN') or @userSecurity.isOwnAccount(#userId, authentication.name)")
public void deleteUserAccount(long userId) {
    userAccountRepository.deleteById(userId);
}
```

The fix requires a collaborating `UserSecurity` bean with the following interface (to be implemented elsewhere):
```java
public interface UserSecurity {
    boolean isOwnAccount(long userId, String username);
}
```

## Explanation

The original method performs a sensitive action (deleting a user account) with only role-based authorization (`hasRole('ADMIN')`), meaning any administrator can delete any user account. This violates CWE-862 because it lacks resource-level authorization—the check that the authenticated caller is permitted to operate on *this specific resource*. The fix adds a resource-level condition using a SpEL expression that invokes a security bean to verify the caller either holds the ADMIN role *or* is deleting their own account. This ensures that non-admin users can only delete their own accounts, while administrators retain the ability to delete any account. The authorization now enforces both the action (who is allowed to delete accounts) and the resource (which accounts the caller may delete).

## Behaviour changes

The authorization logic is now more restrictive:
- **Original**: Any user with ADMIN role can delete any user account.
- **Fixed**: Only ADMIN-role users, or users deleting their own account, can proceed.
- **Method signature**: Unchanged.
- **Return behavior**: Unchanged—the method returns void in both cases.
- **Error behavior**: If the SpEL condition evaluates false, Spring Security's `ExceptionTranslationFilter` will respond with 403 Forbidden for an authenticated user, matching the expected authorization failure response.

This change prevents privilege escalation where an ADMIN could delete arbitrary user accounts without a business relationship to them.
