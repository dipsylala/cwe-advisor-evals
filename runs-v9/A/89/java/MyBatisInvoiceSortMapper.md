## Verdict

Confirmed. `InvoiceMapper.findForTenant` builds its `ORDER BY` clause with MyBatis `${sort}` string substitution, and `sort` is attacker-controlled input passed through unchanged from `InvoiceController.listInvoices`.

## Source

`InvoiceController.listInvoices(String tenantId, String sort)` (InvoiceController.java, line 12) receives `sort` from the caller (an HTTP request parameter in the real application). It substitutes a default of `"created_at"` only when `sort` is `null`, otherwise passes the raw value straight through to `InvoiceService.listInvoices` (InvoiceService.java, line 12), which forwards it unmodified to `InvoiceMapper.findForTenant` (InvoiceMapper.java, line 9).

## Fix

```java
package cases.mybatis;

import java.util.List;
import java.util.Map;

public class InvoiceController {
    private final InvoiceService service;

    public InvoiceController(InvoiceService service) {
        this.service = service;
    }

    public List<InvoiceRow> listInvoices(String tenantId, String sort) {
        return service.listInvoices(tenantId, resolveSort(sort));
    }

    // Allowlist: only these exact ORDER BY fragments are ever handed to the
    // mapper's ${sort} substitution. Anything else falls back to the default.
    private static final Map<String, String> ALLOWED_SORTS = Map.of(
        "created_at", "created_at",
        "created_at_desc", "created_at DESC",
        "total_cents", "total_cents",
        "total_cents_desc", "total_cents DESC",
        "status", "status"
    );

    private String resolveSort(String requestedSort) {
        if (requestedSort == null) {
            return ALLOWED_SORTS.get("created_at");
        }
        String resolved = ALLOWED_SORTS.get(requestedSort);
        return resolved != null ? resolved : ALLOWED_SORTS.get("created_at");
    }
}
```

`InvoiceMapper.java` and `InvoiceService.java` are unchanged; `${sort}` in the `@Select` annotation still performs literal string substitution, but it now only ever receives one of the fixed strings from `ALLOWED_SORTS`.

## Explanation

MyBatis offers two substitution syntaxes: `#{}` produces a bound parameter (sent to the JDBC driver as a placeholder value, never parsed as SQL), while `${}` performs raw string concatenation into the SQL text before it reaches the driver. `#{}` cannot be used here because JDBC placeholders may only stand in for literal values, not for identifiers or keywords such as column names or `ASC`/`DESC` — binding `sort` with `#{sort}` would send it as a quoted string literal and produce invalid SQL (`ORDER BY 'created_at'`), not a working dynamic sort.

Because the sort target is structurally an identifier/direction rather than a value, the only sound fix is to stop treating the request value as SQL text at all. Move the trust boundary to the point where the value originates from the caller (`InvoiceController.listInvoices`) and translate it through a fixed allowlist into one of a small set of known-safe `ORDER BY` fragments before it is ever passed downstream. `InvoiceService` and `InvoiceMapper` then only ever see a value drawn from that fixed set, so `${sort}` substitution is safe by construction: there is no attacker-reachable path that can inject `; DROP TABLE`, `UNION SELECT`, boolean/time-based payloads, or any other SQL syntax into the query, because the mapper never receives arbitrary text — only one of the five hardcoded fragments the controller selects.

An alternative would be to allowlist inside `InvoiceService` or `InvoiceMapper` instead of the controller, which is equally valid; the key requirement is that validation happens before the value is concatenated into SQL, and that unrecognized input is rejected or mapped to a safe default rather than passed through, silently or otherwise.
