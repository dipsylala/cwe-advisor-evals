## Verdict

Confirmed - exploitable. `InvoiceMapper.findForTenant` builds its `ORDER BY` clause with MyBatis `${sort}` text substitution, and the `sort` value flows in from the caller with no validation anywhere on the path.

## Source

`InvoiceController.listInvoices(String tenantId, String sort)` receives `sort` as a caller-supplied parameter (an external, attacker-controllable value in the deployed API - the controller only substitutes a default when it is `null`, it does not validate a supplied value). It passes `sort` unchanged to `InvoiceService.listInvoices`, which passes it unchanged to `InvoiceMapper.findForTenant`.

## Fix

### File: InvoiceService.java

```java
package cases.mybatis;

import java.util.List;
import java.util.Map;

public class InvoiceService {
    private static final Map<String, String> ALLOWED_SORTS = Map.of(
        "created_at", "created_at ASC",
        "created_at_desc", "created_at DESC",
        "total_cents", "total_cents ASC",
        "total_cents_desc", "total_cents DESC",
        "status", "status ASC",
        "status_desc", "status DESC",
        "id", "id ASC",
        "id_desc", "id DESC"
    );

    private final InvoiceMapper mapper;

    public InvoiceService(InvoiceMapper mapper) {
        this.mapper = mapper;
    }

    public List<InvoiceRow> listInvoices(String tenantId, String sort) {
        String canonicalSort = ALLOWED_SORTS.get(sort);
        if (canonicalSort == null) {
            throw new IllegalArgumentException("Unsupported sort value: " + sort);
        }
        return mapper.findForTenant(tenantId, canonicalSort);
    }
}
```

## Explanation

`@Select("SELECT id, status, total_cents FROM invoices WHERE tenant_id = #{tenantId} ORDER BY ${sort}")` uses two different MyBatis substitution mechanisms for two different purposes: `#{tenantId}` becomes a `PreparedStatement` `?` placeholder, so `tenantId` is already handled safely and needed no change. `${sort}` is raw text substitution - MyBatis drops the string directly into the SQL text before the statement is prepared - because `ORDER BY` takes a column/direction identifier, a position `#{}` cannot bind. That makes `${sort}` exactly as unsafe as string concatenation, and since `sort` reaches it unchecked, a caller can supply something like `id) UNION SELECT username, password, 1 FROM users -- ` (or a stacked/time-based payload, depending on driver and DB) and change query structure rather than sort order.

Because the sink needs an identifier position rather than a value, the fix is the allowlist substitution the knowledge base's Java and MyBatis guidance calls for: `ALLOWED_SORTS` is a fixed server-side map from the small set of sort options the application actually supports to their exact, hardcoded `column direction` SQL fragments. `InvoiceService.listInvoices` looks the caller's `sort` up in that map and uses the matched canonical fragment - never the caller's original string - as the value passed down to the mapper. `InvoiceMapper.findForTenant` and its `${sort}` substitution are unchanged: the sink still receives untyped text, but that text is now always one of eight literal strings the application itself wrote, never attacker-influenced content, so no input can alter query structure. `tenantId` continues through `#{tenantId}` exactly as before.

Sink contract carried through: `findForTenant` still returns `List<InvoiceRow>` via the same two bound/substituted parameters, and `InvoiceController` is unmodified - its `sort == null ? "created_at" : sort` default still resolves correctly, since `"created_at"` is a key in the allowlist.

**Check performed:** the fixed `InvoiceService.java` was compiled with `javac` (JDK 26) alongside the unmodified `InvoiceController.java` and a signature-only stub of `InvoiceMapper`/`InvoiceRow` (identical method signature and record shape, annotations stripped since the MyBatis dependency jar wasn't available in the scratch build) in an isolated scratch directory outside the repo. It compiled with no errors or warnings. Every name the fix introduces - `java.util.Map`, `Map.of`, `java.lang.IllegalArgumentException` - is JDK standard library; no new third-party dependency was added.

## Behaviour changes

- A `sort` value outside the eight allowlisted keys (`created_at`, `created_at_desc`, `total_cents`, `total_cents_desc`, `status`, `status_desc`, `id`, `id_desc`) now makes `InvoiceService.listInvoices` throw `IllegalArgumentException` instead of executing a query with that string spliced into `ORDER BY`. Previously any string was accepted and run verbatim. This is a deliberate, necessary tightening - the vulnerable behavior *was* "any string is accepted" - but any legitimate caller currently sending a sort key outside this set (e.g. a bare `"total_cents_desc"`-style typo, or a different sort field the application actually needs) will now get an exception where it previously got a (mis-sorted or dangerous) result. If the application supports additional legitimate sort fields or a separate direction parameter, extend `ALLOWED_SORTS` accordingly before deploying.
- The literal SQL text passed to `${sort}` changed from "whatever the caller sent" to one of the fixed canonical fragments (e.g. `"created_at ASC"` instead of a bare `"created_at"`); the mapper's `ORDER BY ${sort}` still renders correctly since a fragment is valid `ORDER BY` syntax.
