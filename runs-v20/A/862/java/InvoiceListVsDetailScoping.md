## Verdict

Confirmed. `GET /api/invoices` returns every invoice in the system to any authenticated caller, with no ownership check, while the sibling endpoint `GET /api/invoices/{id}` correctly scopes its lookup to the caller via `findByIdAndOwnerUsername`. This is CWE-862 (Missing Authorization): the list endpoint omits the authorization check that the detail endpoint enforces, letting any authenticated user enumerate and read other users' invoice data (amounts, invoice IDs, and other owners' usernames).

## Source

`Authentication authentication` in `listInvoices` (added by the fix) is the trusted identity source, the same one already used by `getInvoice`. The unauthorized data reaches the caller via the sink at `InvoiceController.java` line 26, `repository.findAll()`, which is called with no owner filter and returned directly as the HTTP response body.

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

`InvoiceRepository` already exposes `findByOwnerUsername(String ownerUsername)`, a query scoped to one owner, alongside the unscoped `findAll()`. The list endpoint was calling the unscoped method instead of the scoped one that was clearly provided for this purpose (the detail endpoint's own `findByIdAndOwnerUsername` establishes the same scoping pattern for lookups by ID). The fix adds the `Authentication` parameter Spring Security already injects for `getInvoice`, and replaces `repository.findAll()` with `repository.findByOwnerUsername(authentication.getName())`, so the endpoint returns only the caller's own invoices.

This mirrors the existing, working authorization pattern in the same controller rather than introducing a new mechanism: both endpoints now derive the owner from the authenticated principal and pass it into a repository method that filters at the data-access layer, so an invoice belonging to another user is never loaded into memory or serialized in the response. No new dependency, allowlist, or validation logic is needed — the missing check was simply not wired to the query method that already existed for it.

A regression test for this fix must assert that the returned list contains only invoices whose `ownerUsername` matches the authenticated user, and that calling the endpoint with a different user's invoices present in the backing store does not return them.
