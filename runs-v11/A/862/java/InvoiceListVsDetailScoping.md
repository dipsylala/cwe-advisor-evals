## Verdict
CONFIRMED

## Source
The `listInvoices()` method at line 23-26 in InvoiceController.java lacks authorization. It returns all invoices without verifying the requesting user owns them, while the detail endpoint correctly scopes access per user.

## Fix
Add an `Authentication` parameter and filter by the authenticated user's username:

```java
@GetMapping("/api/invoices")
public List<Invoice> listInvoices(Authentication authentication) {
    return repository.findByOwnerUsername(authentication.getName());
}
```

## Explanation
The detail endpoint `getInvoice()` correctly uses `findByIdAndOwnerUsername()` to ensure a user can only access their own invoice by ID. The list endpoint must apply the same authorization: retrieve only invoices owned by the authenticated user via `findByOwnerUsername()`. Without this check, any authenticated user can enumerate all invoices in the system, a missing authorization vulnerability (CWE-862).
