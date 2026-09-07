## Verdict

The finding is confirmed. The `listInvoices()` endpoint returns all invoices in the system without verifying the caller owns them. An authenticated user can read invoices belonging to any other user.

## Source

The vulnerability spans the endpoint definition and the repository query it invokes:

1. **Endpoint**: `@GetMapping("/api/invoices")` public method at line 23
2. **Repository call**: `repository.findAll()` at line 26
3. **Missing check**: The method accepts an authenticated request but performs no authorization - no role check, no ownership verification, no filtering by the current user

The `getInvoice()` method (line 17-21) shows the correct pattern: it receives the `Authentication` object and uses `repository.findByIdAndOwnerUsername(id, authentication.getName())` to scope the lookup to the current user's data only.

## Fix

The fix adds the missing ownership check by:
1. Accepting the authenticated user via the `Authentication` parameter
2. Filtering the list through `repository.findByOwnerUsername(authentication.getName())` instead of `repository.findAll()`

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

The original code returned the result of `repository.findAll()`, which retrieves every invoice in the system. Adding the `Authentication authentication` parameter gives the handler access to the authenticated user, and passing `authentication.getName()` to `findByOwnerUsername()` scopes the result to only invoices owned by that user. This closes the authorization gap without introducing a new vulnerability - the repository method already implements the ownership filtering that was missing at the application layer, and the 404 response for missing records (from an empty list or the repository's handling) correctly distinguishes "not yours" from "does not exist" without confirming enumeration.

## Behaviour changes

- **Before**: Any authenticated user receives the complete list of all invoices
- **After**: Each authenticated user receives only their own invoices

The HTTP response status follows the existing pattern: a 200 with the filtered list for authorized access, and a 404 or empty list for users with no invoices. No new exception paths are introduced - the `orElseThrow()` in `getInvoice()` still handles the detail endpoint.
