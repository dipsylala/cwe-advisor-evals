## Verdict

- **CWE ID:** CWE-89 (SQL Injection)
- **Verdict:** exploitable
- **Confidence:** high

## Source

- **Source:** the `sort` parameter on `InvoiceController.listInvoices(String tenantId, String sort)` (line 12). It is caller-supplied and only null-checked (`sort == null ? "created_at" : sort`, line 13) - any non-null string is accepted unchanged.
- **Path:** `InvoiceController.listInvoices` -> `InvoiceService.listInvoices(tenantId, sort)` (line 13 of `InvoiceService.java`, no validation) -> `InvoiceMapper.findForTenant(tenantId, sort)`.
- **Sink:** `InvoiceMapper.java` line 8, `@Select("SELECT id, status, total_cents FROM invoices WHERE tenant_id = #{tenantId} ORDER BY ${sort}")`. `tenantId` is bound safely via MyBatis `#{}` (a `PreparedStatement` placeholder). `sort` is spliced with `${}`, MyBatis's raw text-substitution syntax - the string is concatenated directly into the SQL before the statement is prepared, so the `ORDER BY` clause executes whatever the caller supplied, e.g. a subquery or `CASE` expression for boolean/error-based data exfiltration.
- **Sink contract:** returns `List<InvoiceRow>` mapped from the result set; throws MyBatis's unchecked persistence exception on a malformed/failing query; no output is discarded; both parameters are required with no other implicit defaults beyond the controller's null-to-`"created_at"` substitution.

## Fix

No library change is needed; `#{tenantId}` is already correctly parameterized. The `${sort}` substitution is MyBatis's documented (and only) mechanism for a dynamic `ORDER BY` column - it cannot be replaced with `#{}` - so the fix resolves the caller-supplied value against a server-side allowlist and forwards the map's canonical value, never the raw input.

Vulnerable code (`InvoiceService.java`):

```java
public List<InvoiceRow> listInvoices(String tenantId, String sort) {
    return mapper.findForTenant(tenantId, sort);
}
```

Fixed code (`InvoiceService.java`):

```java
import java.util.Map;

private static final Map<String, String> SORT_COLUMNS = Map.of(
    "id", "id",
    "status", "status",
    "total", "total_cents",
    "created_at", "created_at"
);

public List<InvoiceRow> listInvoices(String tenantId, String sort) {
    String safeSort = SORT_COLUMNS.getOrDefault(sort, "created_at");
    return mapper.findForTenant(tenantId, safeSort);
}
```

`InvoiceMapper.java` and `InvoiceController.java` are unchanged - the mapper's `${sort}` stays as the documented pattern for a dynamic column, and the controller's null-to-default logic is preserved; the allowlist substitution is what makes the value reaching it trustworthy.

## Explanation

The vulnerability is that `sort` reaches `${sort}` unvalidated, so MyBatis substitutes it as literal SQL text into the `ORDER BY` clause, letting an attacker inject arbitrary SQL there (e.g. `(CASE WHEN (SELECT ...)=1 THEN id ELSE status END)` for boolean-based exfiltration). Because `ORDER BY` needs a column identifier rather than a bindable value, `#{}` cannot express this position, so the fix does not attempt to parameterize it. Instead, `InvoiceService.listInvoices` maps the caller's `sort` string against a fixed `Map` of permitted sort keys and uses `getOrDefault` to select the matching canonical column name (falling back to `created_at` for anything unrecognized). The value that reaches `${sort}` is now always one of four hard-coded strings chosen server-side, never attacker-controlled text, which closes the injection while preserving the dynamic-ORDER-BY feature.

## Behaviour changes

- Any `sort` value outside the four allowlisted keys (`id`, `status`, `total`, `created_at`) now silently falls back to `created_at` instead of being forwarded verbatim into the SQL string. Previously, any string - including valid alternate columns like `total_cents` directly, or SQL injection payloads - was accepted. This narrowing from "any string" to a four-value allowlist is required to close the injection, since `${}` has no parameterized alternative for this position.
- The public sort key `"total"` now maps to the schema column `total_cents` rather than requiring callers to know or pass the internal column name literally. This decouples the API vocabulary from the schema and is a side effect of introducing the allowlist, not a functional loss - a caller who was already passing `total_cents` directly will now fall through to the `created_at` default instead, since `total_cents` is not itself a map key.
- `InvoiceController`'s null-to-`created_at` default and `tenantId` handling are unchanged; `#{tenantId}` binding in the mapper is unchanged.
