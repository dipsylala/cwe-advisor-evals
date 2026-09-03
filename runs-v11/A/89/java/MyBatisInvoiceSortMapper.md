## Verdict

Confirmed SQL injection via unvalidated sort parameter in MyBatis mapper ORDER BY clause.

## Source

InvoiceMapper.java line 8 uses `${sort}` (string interpolation) to construct the ORDER BY clause:

```
@Select("SELECT id, status, total_cents FROM invoices WHERE tenant_id = #{tenantId} ORDER BY ${sort}")
```

The `sort` parameter flows unvalidated from InvoiceController → InvoiceService → InvoiceMapper, allowing an attacker to inject arbitrary SQL expressions into the ORDER BY clause.

## Fix

Validate the sort parameter against a whitelist of allowed column names before use. MyBatis cannot parameterize ORDER BY column references, so validation is required for any dynamic sort column.

**Updated InvoiceMapper.java:**

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

**Updated InvoiceService.java:**

```java
package cases.mybatis;

import java.util.List;
import java.util.Set;

public class InvoiceService {
    private final InvoiceMapper mapper;
    private static final Set<String> ALLOWED_SORT_COLUMNS = Set.of(
        "id",
        "status",
        "total_cents",
        "created_at"
    );

    public InvoiceService(InvoiceMapper mapper) {
        this.mapper = mapper;
    }

    public List<InvoiceRow> listInvoices(String tenantId, String sort) {
        String validatedSort = validateSort(sort);
        return mapper.findForTenant(tenantId, validatedSort);
    }

    private String validateSort(String sort) {
        if (sort == null || !ALLOWED_SORT_COLUMNS.contains(sort)) {
            return "created_at";
        }
        return sort;
    }
}
```

**InvoiceController.java** remains unchanged (already passes default):

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

## Explanation

The vulnerability occurs because MyBatis' `${}` syntax performs string interpolation without escaping, making it unsuitable for dynamic SQL identifiers. Unlike prepared statement parameters (`#{}`), which prevent injection of SQL syntax, `${}` simply concatenates the value into the SQL string.

ORDER BY clauses require column names (identifiers), which cannot be parameterized with prepared statement syntax in any SQL dialect. The only safe approach is to validate the sort parameter against an explicit allowlist of permitted column names.

The fix adds a private `validateSort()` method in the service layer that:
1. Defines `ALLOWED_SORT_COLUMNS` as a static set of valid column names the API may sort by
2. Rejects any sort value not in this set, falling back to a safe default (`created_at`)
3. Returns only validated column names to the mapper

This ensures that even if an attacker sends `sort=id; DROP TABLE invoices`, the value fails validation and the query executes with the default sort column instead. The attacker cannot inject arbitrary SQL.

