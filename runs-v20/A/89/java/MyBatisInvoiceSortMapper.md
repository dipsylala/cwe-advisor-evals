## Verdict

Confirmed true positive. `InvoiceMapper.findForTenant` builds its SQL with MyBatis `${sort}` text substitution, so whatever string reaches that parameter is spliced verbatim into the `ORDER BY` clause. `tenantId` is safely bound with `#{tenantId}`, but `#{}` binding cannot be used for `sort` because it is not a value in a comparison, it is a column/direction identifier, and MyBatis has no way to parameterize an identifier position. Any caller that forwards attacker-controlled text into this parameter allows arbitrary SQL to be appended to the query (stacked expressions, subqueries, boolean/time-based blind injection, etc.).

## Source

`InvoiceController.listInvoices(String tenantId, String sort)` accepts `sort` directly from the caller (only substituting a default when it is `null`) and passes it unchanged into `InvoiceService.listInvoices`, which forwards it unchanged into `InvoiceMapper.findForTenant`, where it is interpolated by `${sort}` into the SQL text executed against the database. There is no validation or allowlisting anywhere on this path before the value reaches the SQL sink.

## Fix

### File: InvoiceService.java
```java
package cases.mybatis;

import java.util.List;
import java.util.Map;

public class InvoiceService {
    private static final String DEFAULT_SORT_KEY = "created_at";

    // Fixed, code-defined SQL fragments only. The lookup key is attacker
    // controlled; the SQL text on the right-hand side never is. Any sort
    // key that is not in this map falls back to the default rather than
    // reaching the ${sort} substitution in the mapper.
    private static final Map<String, String> ALLOWED_SORTS = Map.of(
        "created_at", "created_at ASC",
        "created_at_desc", "created_at DESC",
        "total_cents", "total_cents ASC",
        "total_cents_desc", "total_cents DESC",
        "status", "status ASC",
        "status_desc", "status DESC"
    );

    private final InvoiceMapper mapper;

    public InvoiceService(InvoiceMapper mapper) {
        this.mapper = mapper;
    }

    public List<InvoiceRow> listInvoices(String tenantId, String sort) {
        String safeSort = ALLOWED_SORTS.getOrDefault(sort, ALLOWED_SORTS.get(DEFAULT_SORT_KEY));
        return mapper.findForTenant(tenantId, safeSort);
    }
}
```

## Explanation

`#{}` in MyBatis produces a bound `PreparedStatement` parameter, which only works where the database accepts a value placeholder - it cannot bind a column name or sort direction, so switching `${sort}` to `#{sort}` would either throw or silently sort by a literal string rather than the intended column, and would not remove the vulnerability. `tenantId` was never the issue; it was already bound correctly.

The only correct fix for a `${}` identifier substitution is to guarantee that no attacker-influenced text ever reaches it. `InvoiceService.listInvoices` now uses the caller-supplied `sort` value purely as a lookup key into a fixed, compile-time map of allowed sort fragments; the string actually passed to `mapper.findForTenant` - and therefore substituted by `${sort}` - is always one of the literal values written in that map. An unrecognized or malicious `sort` value (including SQL metacharacters, comments, or stacked clauses) simply misses the map and falls back to the default `created_at ASC` ordering instead of being rejected with an error, matching the existing `null`-defaulting behavior in the controller. Legitimate sort choices (by creation time, amount, or status, ascending or descending) continue to work and still return `InvoiceRow` records; no arbitrary SQL fragment can reach the query.
