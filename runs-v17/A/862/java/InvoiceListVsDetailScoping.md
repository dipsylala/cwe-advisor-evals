## Verdict
CONFIRMED — Missing authorization check in list operation. The `/api/invoices` endpoint returns all invoices from all users without verifying the current user's identity or ownership, violating the principle of least privilege that the detail endpoint (`/api/invoices/{id}`) correctly implements.

## Source
The `listInvoices()` method at line 23-27 exposes `repository.findAll()` via an unauthenticated query, returning all invoices regardless of user identity. Line 18-21 shows the correct pattern: the `getInvoice()` detail method accepts `Authentication`, retrieves the current user's name, and filters to only that user's records via `findByIdAndOwnerUsername()`.

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
The fix applies the same authorization pattern from `getInvoice()` to the list operation: inject `Authentication` to retrieve the authenticated user's name, and query the repository using `findByOwnerUsername()` instead of `findAll()`. This ensures each user sees only their own invoices, preventing horizontal privilege escalation where users could enumerate or access invoices belonging to other users. The repository already provides the scoped query method; the controller must use it.
