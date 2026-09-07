## Verdict

CONFIRMED. The `listInvoices()` method at line 24–27 of InvoiceController.java lacks authorization checks and returns all invoices regardless of caller identity, violating CWE-862. The `getInvoice()` method demonstrates the correct pattern—scoping queries to the authenticated user's own records—but `listInvoices()` omits this check entirely.

## Source

**File:** InvoiceController.java
**Method:** listInvoices() at line 24
**Sink:** repository.findAll() at line 26

**Data Flow:**
1. The endpoint `/api/invoices` (line 23) is marked `@GetMapping` and requires only Spring's global authentication filter.
2. The `listInvoices()` method does not accept an `Authentication` parameter, so it has no way to identify the caller.
3. It calls `repository.findAll()`, which returns invoices from all users in the system.
4. Any authenticated user—even one with no admin role—can enumerate all invoices.

**Comparison:** The sibling endpoint `/api/invoices/{id}` (line 17) demonstrates the correct implementation: it accepts `Authentication authentication`, extracts the caller's username, and calls `repository.findByIdAndOwnerUsername(id, authentication.getName())` to scope the result to the caller's own records. This pattern must be applied to `listInvoices()`.

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

The fix adds two changes to `listInvoices()`:

1. **Add Authentication parameter** (line 24): `listInvoices(Authentication authentication)` allows Spring Security to inject the authenticated user's identity. Spring automatically resolves this parameter at runtime.
2. **Scope the repository call** (line 26): Replace `repository.findAll()` with `repository.findByOwnerUsername(authentication.getName())`. This reuses the existing `findByOwnerUsername()` method already available in InvoiceRepository, ensuring the caller sees only invoices they own.

This change mirrors the resource-level access pattern already used by `getInvoice()` and eliminates the authorization gap. The method now enforces the CWE-862 remedy from the knowledge base: "Check ownership against a server-loaded copy of the resource" and "scope the lookup itself — `WHERE owner_id = ?`" so the query returns only the caller's records.

The `Authentication` class is already imported (line 4), and `authentication.getName()` is the standard Spring Security method to retrieve the authenticated user's username. The `repository.findByOwnerUsername()` method already exists in InvoiceRepository (line 11), so no new repository method needs to be added.

## Behaviour changes

- **Before:** The `/api/invoices` endpoint returns all invoices in the system, regardless of which user is calling it (as long as they are authenticated).
- **After:** The `/api/invoices` endpoint returns only the invoices owned by the authenticated caller.
- **Impact on authorized users:** Users with legitimate access to their own invoices see the same data; no change to their behavior.
- **Impact on unauthorized users:** Authenticated users who previously could enumerate all invoices in the system now see only their own. Attempts to call the endpoint with proper authentication succeed, but only their scoped data is returned.
- **No other code paths affected:** The fix only modifies `listInvoices()`; `getInvoice()` and all other application logic remain unchanged.
