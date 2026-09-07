## Verdict

Confirmed: SQL Injection via MyBatis raw text substitution (`${sort}`). The `sort` parameter flows from the untrusted HTTP request through InvoiceController → InvoiceService → InvoiceMapper, where it is interpolated directly into the SQL query using MyBatis's `${}` operator, which performs raw text substitution without parameterization. An attacker can inject arbitrary SQL (e.g., `created_at; DROP TABLE invoices; --`) to manipulate the query logic.

## Source

InvoiceController.listInvoices(String tenantId, String sort) receives the `sort` parameter from an HTTP request (typically a Spring MVC `@RequestParam`), defaulting to `"created_at"` if null. The parameter is passed through InvoiceService to InvoiceMapper.findForTenant(), where it is used directly in the SQL query.

## Fix

### File: InvoiceService.java

```java
package cases.mybatis;

import java.util.List;
import java.util.Map;

public class InvoiceService {
    private final InvoiceMapper mapper;

    public InvoiceService(InvoiceMapper mapper) {
        this.mapper = mapper;
    }

    public List<InvoiceRow> listInvoices(String tenantId, String sort) {
        String safeSortColumn = validateAndGetSortColumn(sort);
        return mapper.findForTenant(tenantId, safeSortColumn);
    }

    private String validateAndGetSortColumn(String sort) {
        // Define permitted sort columns as a server-side allowlist
        Map<String, String> permittedSortColumns = Map.of(
            "created_at", "created_at",
            "id", "id",
            "status", "status",
            "total_cents", "total_cents"
        );

        String safeSortColumn = permittedSortColumns.get(sort);
        if (safeSortColumn == null) {
            // Default to created_at if sort is not in the allowlist
            safeSortColumn = "created_at";
        }
        return safeSortColumn;
    }
}
```

### File: InvoiceController.java

```java
package cases.mybatis;

import java.util.List;

public class InvoiceController {
    private final InvoiceService service;

    public InvoiceController(InvoiceService service) {
        this.service = service;
    }

    public List<InvoiceRow> listInvoices(String tenantId, String sort) {
        return service.listInvoices(tenantId, sort == null ? "created_at" : sort);
    }
}
```

### File: InvoiceMapper.java

```java
package cases.mybatis;

import java.util.List;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

public interface InvoiceMapper {
    @Select("SELECT id, status, total_cents FROM invoices WHERE tenant_id = #{tenantId} ORDER BY ${sort}")
    List<InvoiceRow> findForTenant(@Param("tenantId") String tenantId, @Param("sort") String sort);
}

record InvoiceRow(String id, String status, long totalCents) {}
```

## Explanation

The fix adds allowlist validation in InvoiceService.validateAndGetSortColumn() to prevent SQL injection. The method:

1. **Defines a server-side allowlist** using a Map containing all permitted sort columns (`created_at`, `id`, `status`, `total_cents`)
2. **Validates the input** by looking up the `sort` parameter in the allowlist map
3. **Ensures only server-controlled values reach the SQL query** by passing the matched value (or a safe default) to the mapper, never the original untrusted input
4. **Maintains MyBatis's `${sort}` mechanism** because the value is now guaranteed to be one of the permitted column names from the server-side map

Per the CWE-89 Java guidance: "Treat a dynamic identifier as a key into a server-side map of permitted names, not as input to validate and then use - the value reaching the query should be the map's, never the caller's." This implementation follows that pattern exactly. The `sort` parameter is treated as a key to look up the safe column name in the allowlist, and only the mapped value is passed downstream.

Note: While MyBatis's `#{}` operator could parameterize values, it cannot safely bind SQL structural elements like column names. The `${}` operator is the correct mechanism for dynamic identifiers, but only when the value comes from a server-controlled allowlist, not from untrusted input.

## Behaviour changes

- **Query structure**: No change. The SQL query remains `SELECT id, status, total_cents FROM invoices WHERE tenant_id = #{tenantId} ORDER BY ${sort}`.
- **Valid requests**: Requests with `sort` values matching the allowlist (e.g., `created_at`, `id`, `status`, `total_cents`) continue to work identically.
- **Invalid sort values**: Requests with `sort` values outside the allowlist (e.g., `invalid_column`, `123`, malicious payloads) now default to `created_at` instead of being interpolated into the query. This is a safe fallback that prevents injection while maintaining usability.
- **Security improvement**: SQL injection via the `sort` parameter is eliminated because attacker-controlled strings are never used to construct the query; only allowlist values are.
