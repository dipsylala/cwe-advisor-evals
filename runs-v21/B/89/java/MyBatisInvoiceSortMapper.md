## Verdict

Real SQL injection via unsafe MyBatis `${}` substitution of user-controlled sort column name.

## Source

**Entry Point:** InvoiceController.listInvoices(String tenantId, String sort) - `sort` parameter is user-controlled via HTTP request parameter.

**Data Flow:**
1. User supplies `sort` parameter (no validation in controller)
2. Controller passes to InvoiceService.listInvoices()
3. Service passes to InvoiceMapper.findForTenant()
4. Mapper embeds in SQL via `${sort}` (line 8) - unsafe raw substitution

**Sink:** InvoiceMapper line 8 - `ORDER BY ${sort}` in MyBatis `@Select` annotation performs text substitution without sanitization.

**Exploitable:** Yes. Attacker can inject SQL via sort parameter: `created_at DESC; DROP TABLE invoices; --` results in executed SQL: `ORDER BY created_at DESC; DROP TABLE invoices; --`

## Fix

### File: InvoiceMapper.java

```java
package cases.mybatis;

import java.util.List;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

public interface InvoiceMapper {
    @Select("SELECT id, status, total_cents FROM invoices WHERE tenant_id = #{tenantId} ORDER BY created_at")
    List<InvoiceRow> findForTenantByCreatedAt(@Param("tenantId") String tenantId);

    @Select("SELECT id, status, total_cents FROM invoices WHERE tenant_id = #{tenantId} ORDER BY total_cents")
    List<InvoiceRow> findForTenantByTotal(@Param("tenantId") String tenantId);

    @Select("SELECT id, status, total_cents FROM invoices WHERE tenant_id = #{tenantId} ORDER BY status")
    List<InvoiceRow> findForTenantByStatus(@Param("tenantId") String tenantId);
}

record InvoiceRow(String id, String status, long totalCents) {}
```

### File: InvoiceService.java

```java
package cases.mybatis;

import java.util.List;

public class InvoiceService {
    private final InvoiceMapper mapper;

    public InvoiceService(InvoiceMapper mapper) {
        this.mapper = mapper;
    }

    public List<InvoiceRow> listInvoices(String tenantId, String sort) {
        String sortColumn = (sort == null) ? "created_at" : sort;
        
        return switch (sortColumn) {
            case "created_at" -> mapper.findForTenantByCreatedAt(tenantId);
            case "total_cents" -> mapper.findForTenantByTotal(tenantId);
            case "status" -> mapper.findForTenantByStatus(tenantId);
            default -> throw new IllegalArgumentException("Invalid sort column: " + sortColumn);
        };
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
        return service.listInvoices(tenantId, sort);
    }
}
```

## Explanation

The original code used MyBatis's `${}` placeholder for the sort column name, which performs unsafe raw text substitution. Since SQL identifiers (column names) cannot use parameterized `#{}` placeholders, the code attempted to handle this with `${}`, but without any validation of the input.

The fix eliminates the injection vector by:

1. **Removing dynamic SQL construction** - Replaced the single method with three separate, hardcoded queries, each with a static, safe `ORDER BY` clause. This follows the guidance principle: "a sort parameter accepting `created_at` or `total` is usually a fixed set of queries wearing a dynamic costume."

2. **Validating sort input via explicit routing** - The service layer now validates the sort parameter against an implicit allowlist (the cases in the switch statement). Only recognized sort columns (`created_at`, `total_cents`, `status`) are accepted; any other value throws an `IllegalArgumentException`.

3. **Using only parameterized values** - The `tenantId` continues to use `#{tenantId}` (parameterized), ensuring that both the filter condition and sort order are now protected from injection.

This approach makes SQL injection impossible because the sort column is never constructed from user input—it is always one of three hardcoded, pre-approved identifiers chosen by the application logic, not the attacker.

## Behaviour changes

- **Allowed sort columns are now enforced**: Only `"created_at"`, `"total_cents"`, and `"status"` are accepted. Any other sort value raises `IllegalArgumentException`.
- **Default sort is preserved**: When `sort` is `null`, the default remains `"created_at"`.
- **API remains unchanged**: Callers of `listInvoices()` see no signature change, but invalid sort parameters now raise an exception instead of executing arbitrary SQL.
- **Query performance is identical**: Each sort option uses a dedicated prepared statement; there is no performance difference from the original single-query approach.
