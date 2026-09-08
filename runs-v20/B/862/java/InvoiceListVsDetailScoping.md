## Verdict

exploitable (confidence: high)

CWE-862 (Missing Authorization) at `InvoiceController.java:26`. `listInvoices()` is reachable by any authenticated caller and returns every invoice in the system with no ownership scoping, while the sibling endpoint `getInvoice()` on the same resource correctly scopes its lookup to the caller via `findByIdAndOwnerUsername`. The list endpoint is the one path on this resource that skips that check.

## Source

HTTP `GET /api/invoices`, handled by `InvoiceController.listInvoices()`. The caller is any authenticated principal - `@RestController` methods run behind the global authentication filter but this method adds no further check, unlike `getInvoice`, which requires the `Authentication` the framework injects to match the invoice's `ownerUsername`.

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

`listInvoices()` called `repository.findAll()`, an unscoped query that returns every invoice regardless of who owns it - the sink identified in the finding. `InvoiceRepository` already exposes `findByOwnerUsername(String ownerUsername)`, the same shape of scoped-lookup method the detail endpoint uses (`findByIdAndOwnerUsername`), so the fix adds an `Authentication` parameter (the same type and injection Spring already provides to `getInvoice`) and calls that existing repository method with `authentication.getName()` in place of `findAll()`. This closes the gap by construction: the query itself can only return rows the caller owns, rather than filtering a full result set after the fact, so there is no way to reach another user's invoices through this endpoint. No new dependency, method, or annotation was introduced - the fix reuses a method the repository already defines.

## Behaviour changes

- `listInvoices` now requires an `Authentication` in scope, matching `getInvoice` - not a change in what a legitimate caller can do, since every existing caller is already authenticated to reach this controller.
- The response body changes from "every invoice in the system" to "invoices owned by the calling user." This is the intended effect of closing the missing-authorization gap, not a side effect.
- An authenticated user with no invoices now receives an empty list rather than the previous full-table result; this is consistent with the return type (`List<Invoice>`, never null/404 for a collection) and matches how `findByOwnerUsername` already behaves for `getInvoice`'s equivalent case.
- No change to `getInvoice`, `Invoice`, or `InvoiceRepository` - `findByOwnerUsername` was already present and unused, so no repository code was added.

## Verification

Compiled the fixed `InvoiceController.java` with `javac` (JDK 26) in a scratch directory, against `Invoice.java` and `InvoiceRepository.java` copied unmodified from the case, plus minimal local stand-ins for the three Spring annotation types and `Authentication` (the real Spring Security/Web jars are not vendored in this fixture) - `Authentication.getName()`, `@GetMapping`, `@PathVariable`, `@RestController` all match the interfaces already used by the untouched `getInvoice` method. `javac` produced no errors or warnings. `findByOwnerUsername(String)` was confirmed to already exist in the provided `InvoiceRepository.java` with a matching signature, so no repository change was required.

## Assumptions

None - `findByOwnerUsername` was already defined in `InvoiceRepository` with the exact signature needed, so the fix required no new method, library, or version judgment.
