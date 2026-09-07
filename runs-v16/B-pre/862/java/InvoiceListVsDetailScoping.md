## Verdict

Missing Authorization confirmed. The `listInvoices()` endpoint returns all invoices in the system without verifying that the authenticated user owns them, violating resource-level access control.

## Source

Attacker-controlled source: any authenticated user calling `GET /api/invoices`.

## Fix

**Vulnerable code:**

```java
@GetMapping("/api/invoices")
public List<Invoice> listInvoices() {
    // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    return repository.findAll();  // Returns all invoices for all users
}
```

**Fixed code:**

```java
@GetMapping("/api/invoices")
public List<Invoice> listInvoices(Authentication authentication) {
    return repository.findByOwnerUsername(authentication.getName());
}
```

## Explanation

The vulnerability exists because `listInvoices()` calls `repository.findAll()`, which returns invoices for all users regardless of who is making the request. The method receives no authorization parameter and performs no ownership check.

The fix adds the `Authentication` parameter and passes the authenticated user's username to `repository.findByOwnerUsername(username)`, which already exists in the codebase. This scopes the query to return only invoices owned by the requesting user, closing the gap. The pattern mirrors the safe implementation already present in the `getInvoice()` method (lines 18-20), which verifies ownership for individual invoice lookups.

## Behaviour changes

- **Before**: `GET /api/invoices` returned all invoices in the system; any authenticated user could enumerate and access all invoices belonging to other users.
- **After**: `GET /api/invoices` returns only the invoices owned by the authenticated user making the request.
- **Response code**: Remains 200 for the authenticated user's invoices; empty 200 response if the user has no invoices (same as before, but with scoped data).
