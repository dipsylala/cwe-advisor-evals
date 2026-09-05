## Verdict

CONFIRMED. The `listInvoices()` endpoint at line 26 returns all invoices without verifying the current user owns them, violating authorization requirements.

## Source

```java
@GetMapping("/api/invoices")
public List<Invoice> listInvoices() {
    return repository.findAll();
}
```

The sink is `repository.findAll()` which exposes all invoices regardless of ownership.

## Fix

```java
@GetMapping("/api/invoices")
public List<Invoice> listInvoices(Authentication authentication) {
    return repository.findByOwnerUsername(authentication.getName());
}
```

## Explanation

The `getInvoice()` detail endpoint correctly restricts results to invoices owned by the authenticated user via `findByIdAndOwnerUsername()`. The `listInvoices()` list endpoint must apply the same ownership check to prevent users from viewing other users' invoices.

The fix adds the `Authentication` parameter and uses `findByOwnerUsername()` to filter the list to only invoices belonging to the current user, determined by `authentication.getName()`. This mirrors the authorization pattern already established in the detail endpoint and leverages the existing repository method designed for this purpose.
