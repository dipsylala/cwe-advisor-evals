## Verdict

Real SQL injection vulnerability. The `sort` parameter flows from user input (via controller) to MyBatis `${sort}` substitution in the ORDER BY clause without validation. Dynamic column names cannot use MyBatis's safe `#{}` parameterization, so the input must be validated against an allowlist before reaching the query.

## Source

User input enters through `InvoiceController.listInvoices(String sort)` (line 12), flows through `InvoiceService.listInvoices()` (line 12), and reaches the mapper's `@Select` annotation (line 8 of InvoiceMapper.java) where it is substituted directly into the SQL query via `${sort}`.

## Fix

**Define a safe sort column enum or map in the service layer:**

```java
package cases.mybatis;

import java.util.Map;

public class InvoiceService {
    private final InvoiceMapper mapper;
    
    // Canonical mapping of allowed sort parameters to safe SQL identifiers
    private static final Map<String, String> VALID_SORT_COLUMNS = Map.of(
        "created_at", "created_at",
        "id", "id",
        "status", "status",
        "total", "total_cents"
    );

    public InvoiceService(InvoiceMapper mapper) {
        this.mapper = mapper;
    }

    public List<InvoiceRow> listInvoices(String tenantId, String sort) {
        // Resolve the sort parameter against the allowlist
        String validSort = VALID_SORT_COLUMNS.get(sort);
        if (validSort == null) {
            throw new IllegalArgumentException("Invalid sort column: " + sort);
        }
        // Pass only the validated canonical value from the map, never the raw input
        return mapper.findForTenant(tenantId, validSort);
    }
}
```

**No change to InvoiceMapper.java or InvoiceController.java is required.** The controller can safely pass untrusted sort values; the service validates and maps them to safe canonical values before passing to the mapper. The mapper receives only values from the allowlist.

## Explanation

MyBatis's `${}` syntax performs raw text substitution and cannot distinguish between identifiers and values. Column names, table names, and ORDER BY directions are identifiers that cannot be passed as bound parameters (MyBatis's `#{}` syntax is restricted to value positions). The fix validates the `sort` parameter against a server-side map of permitted sort columns and substitutes only the matched canonical value. The map enforces that only specific, pre-defined column names reach the SQL query. The raw user input is never concatenated into the query; it is used only as a key lookup, and the value reaching the mapper comes from the map. If the sort parameter does not match a key, an exception is thrown before the query executes.

## Behaviour changes

The application now rejects unknown sort column names with an `IllegalArgumentException` instead of passing them to the database. Callers must provide one of the allowed sort values: `created_at`, `id`, `status`, or `total`. This is a desirable behaviour change—the API now explicitly documents which sort columns are supported. The default sort order (`created_at`) provided by the controller remains intact and will pass validation.
