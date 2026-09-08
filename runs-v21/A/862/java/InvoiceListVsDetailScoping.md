## Verdict

Confirmed CWE-862 (Missing Authorization). The `/api/invoices` endpoint exposes a complete list of all invoices without verifying that the authenticated user owns them. An attacker with valid authentication credentials can retrieve invoices belonging to other users.

## Source

The vulnerable code at line 26:

```java
@GetMapping("/api/invoices")
public List<Invoice> listInvoices() {
    return repository.findAll();
}
```

The `/api/invoices` endpoint calls `findAll()` without any ownership verification, whereas the `/api/invoices/{id}` endpoint at line 19 correctly restricts results using `findByIdAndOwnerUsername()` to check the authenticated user owns the requested invoice.

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

The fix applies authorization checks consistent with the existing `/api/invoices/{id}` endpoint:

1. **Inject Authentication**: Add the `Authentication` parameter to `listInvoices()` to access the authenticated user's identity, matching the pattern already used in `getInvoice()`.

2. **Use owner-scoped repository method**: Call `findByOwnerUsername(authentication.getName())` instead of `findAll()`. This method already exists in the repository and is the correct equivalent of `findByIdAndOwnerUsername()` for list operations.

3. **Enforce consistent authorization**: Both list and detail endpoints now verify that the authenticated user owns the invoices being accessed. An unauthenticated request or an authenticated user will only see their own invoices.

This change ensures the application enforces user-owned data scoping across all invoice retrieval endpoints, preventing horizontal privilege escalation.

