## Verdict

CWE-862: Missing Authorization confirmed. The `listInvoices()` endpoint returns all invoices in the system without verifying that the authenticated user owns them.

## Source

The vulnerability is at line 26 in `InvoiceController.listInvoices()`, where `repository.findAll()` returns invoices without any ownership constraint. The contrast with `getInvoice()` (lines 18-21) is instructive: that method correctly uses `findByIdAndOwnerUsername(id, authentication.getName())` to scope the result to the authenticated user's own invoice. The list endpoint has no equivalent guard.

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

The fix adds the `Authentication` parameter to `listInvoices()` and replaces the unguarded `repository.findAll()` with `repository.findByOwnerUsername(authentication.getName())`. This scopes the result to invoices owned by the authenticated user, enforcing authorization at the repository level—the same pattern used in `getInvoice()`. The change eliminates the CWE-862 gap by ensuring that the authorization check (ownership verification) is present and executed before the sensitive data (invoices) is returned.

## Behaviour changes

- `listInvoices()` now requires an authenticated user to be injected, making the authentication requirement explicit and available in the method.
- The endpoint now returns only invoices owned by the authenticated user, not all invoices in the system.
- An authenticated user with no invoices receives an empty list instead of observing other users' data.
