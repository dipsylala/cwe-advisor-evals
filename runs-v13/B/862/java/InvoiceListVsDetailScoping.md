## Verdict

VULNERABLE

## Source

The `listInvoices()` method at line 26 in `InvoiceController.java` calls `repository.findAll()` without any authorization check, returning all invoices in the system to any authenticated caller, regardless of ownership.

## Fix

```java
@GetMapping("/api/invoices")
@PreAuthorize("isAuthenticated()")
public List<Invoice> listInvoices(Authentication authentication) {
    return repository.findByOwnerUsername(authentication.getName());
}
```

**Changes:**
1. Add `@PreAuthorize("isAuthenticated()")` annotation to ensure only authenticated users can access this endpoint
2. Add `Authentication authentication` parameter to receive the current user's security context
3. Replace `repository.findAll()` with `repository.findByOwnerUsername(authentication.getName())` to filter invoices to only those owned by the current user

## Explanation

The vulnerability stems from missing resource-level authorization: the endpoint verifies the caller is authenticated but never checks whether they own the invoices being returned. By calling `repository.findAll()`, it exposes all invoices to any logged-in user.

The fix closes this gap by adopting the same pattern already used in the `getInvoice` method: retrieving the authenticated user's name via `authentication.getName()` and using it to filter results through an existing repository method. The `@PreAuthorize("isAuthenticated()")` annotation provides defense-in-depth by explicitly requiring authentication at the method level, ensuring the authorization policy is centralized and consistent with Spring Security best practices.

The repository's scoped query method `findByOwnerUsername` enforces ownership at the data access layer, which is the appropriate defense according to CWE-862 guidance: "Check ownership against a server-loaded copy of the resource" and "Where ownership of a guessable identifier is [the gate], scope the lookup itself - `WHERE id = ? AND owner_id = ?`".

## Behaviour changes

- The endpoint now requires an authenticated user (previously allowed any caller)
- The endpoint now returns only invoices owned by the authenticated user (previously returned all invoices)
- Unauthenticated callers receive a 401 Unauthorized or redirect to login (previously received all data)
- Authenticated users with no owned invoices receive an empty list (previously could enumerate all invoices in the system)
- The return type and success response remain a 200 with a JSON list; the list contents are now filtered
