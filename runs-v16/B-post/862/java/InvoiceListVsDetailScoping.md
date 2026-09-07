## Verdict

The `listInvoices()` endpoint performs a sensitive action (listing invoices) without authorization. Any authenticated user can retrieve all invoices in the system, regardless of ownership. The authorization check is absent, not wrong.

## Source

An HTTP GET request to `/api/invoices` endpoint. The request is authenticated (Spring Security provides the `Authentication` object), but no authorization check verifies the caller may see all invoices.

## Fix

**Vulnerable code (line 23-27):**
```java
@GetMapping("/api/invoices")
public List<Invoice> listInvoices() {
    // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    return repository.findAll();
}
```

**Fixed code:**
```java
@GetMapping("/api/invoices")
@PreAuthorize("hasRole('ADMIN')")
public List<Invoice> listInvoices(Authentication authentication) {
    return repository.findByOwnerUsername(authentication.getName());
}
```

## Explanation

The fix closes the weakness by adding two layers of authorization:

1. **Method-level authorization**: The `@PreAuthorize("hasRole('ADMIN')")` annotation restricts the endpoint to users with the ADMIN role, leveraging Spring Security's method security. This requires `@EnableMethodSecurity` to be active in the application's security configuration.

2. **Data-level scoping**: The repository call changes from `findAll()` to `findByOwnerUsername()`, filtering the results to only invoices owned by the authenticated user. This applies the principle of resource-level authorization - a role check alone is insufficient; the query must be scoped to the user's owned resources.

This pattern mirrors the already-correct `getInvoice()` method (lines 17-21), which uses `findByIdAndOwnerUsername()` to combine resource ownership with retrieval. The fix aligns the list endpoint with this established secure pattern.

## Behaviour changes

- The endpoint now requires the caller to hold the ADMIN role; callers without this role receive a 403 Forbidden response from `ExceptionTranslationFilter`.
- The response payload changes from all invoices in the system to only invoices owned by the authenticated user, even if the caller holds the ADMIN role. If listing behavior should differ by role (e.g., admins see all, regular users see their own), split the implementation into two endpoints or add role-conditional logic inside the method.
- The method signature adds the `Authentication` parameter to extract the username; this is injected by Spring and does not come from the request.
- Request handling relies on Spring Security's proxy-based method security, so the authorization check runs before the method is invoked and applies to any caller using the Spring proxy, including other service methods that delegate to this controller.
