## Verdict

The `listInvoices()` endpoint returns all invoices in the system without verifying the authenticated caller owns them. This allows any authenticated user to enumerate all invoices, regardless of ownership. The fix adds an ownership check by accepting the authenticated user's identity and scoping the repository query to their invoices only.

## Source

The vulnerable code path is:
1. `InvoiceController.listInvoices()` (line 26) calls `repository.findAll()` 
2. Returns the full list of invoices without resource-level authorization
3. `InvoiceRepository.findAll()` returns all invoices in the system

The `getInvoice(id)` method demonstrates the correct pattern: it uses `findByIdAndOwnerUsername(id, authentication.getName())` to scope access to the authenticated user's own record.

## Fix

### File: InvoiceController.java

```java
package cases.authorization;

import java.util.List;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class InvoiceController {
    private final InvoiceRepository repository;

    public InvoiceController(InvoiceRepository repository) {
        this.repository = repository;
    }

    @GetMapping("/api/invoices/{id}")
    public Invoice getInvoice(@PathVariable Long id, Authentication authentication) {
        return repository.findByIdAndOwnerUsername(id, authentication.getName())
                .orElseThrow();
    }

    @GetMapping("/api/invoices")
    public List<Invoice> listInvoices(Authentication authentication) {
        return repository.findByOwnerUsername(authentication.getName());
    }
}
```

## Explanation

The fix adds ownership checking to the `listInvoices()` endpoint by:

1. **Accepting the authenticated user's identity** - Add `Authentication authentication` parameter so the handler can retrieve the current user's username via `authentication.getName()`, matching the pattern already established in `getInvoice()`

2. **Scoping the repository query** - Replace `repository.findAll()` with `repository.findByOwnerUsername(authentication.getName())`, which returns only invoices owned by the authenticated user

3. **Leveraging existing safe methods** - The `InvoiceRepository` already provides `findByOwnerUsername()`, confirming the application has the infrastructure to scope queries safely; the vulnerability is that `listInvoices()` bypassed it

This approach follows CWE-862 guidance for Java: prefer repository methods scoped by owner over inline checks, so the database layer enforces the boundary and every caller accessing the entity through that bean inherits the same protection.

## Behaviour changes

- **Before**: Any authenticated user receives `List<Invoice>` containing all invoices in the system via `/api/invoices`, regardless of ownership
- **After**: Any authenticated user receives `List<Invoice>` containing only invoices where `ownerUsername` matches their username
- **Status code**: Remains 200 for both cases (the list is scoped, not denied based on identity)
- **Impact on legitimate users**: Users can now list only their own invoices; users attempting to enumerate invoices belonging to other users receive an empty list instead
- **Database query**: Changes from `SELECT * FROM invoices` to `SELECT * FROM invoices WHERE owner_username = ?`
