## Verdict
Real: SQL injection via unvalidated dynamic column name in ORDER BY clause.

## Source
The vulnerability exists in `InvoiceMapper.java` line 8, where the `sort` parameter is directly interpolated into the SQL query using MyBatis's `${}` syntax:
```
ORDER BY ${sort}
```
This bypasses parameterization and allows an attacker to inject SQL commands through the sort parameter. The parameter flows from the HTTP layer (InvoiceController) through the service layer (InvoiceService) to the mapper without validation.

## Fix

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

### File: InvoiceService.java
```java
package cases.mybatis;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class InvoiceService {
    private final InvoiceMapper mapper;
    private static final Set<String> ALLOWED_SORT_COLUMNS = new HashSet<>(
        List.of("id", "status", "total_cents", "created_at")
    );

    public InvoiceService(InvoiceMapper mapper) {
        this.mapper = mapper;
    }

    public List<InvoiceRow> listInvoices(String tenantId, String sort) {
        String validatedSort = validateSortColumn(sort);
        return mapper.findForTenant(tenantId, validatedSort);
    }

    private String validateSortColumn(String sort) {
        if (sort == null || sort.trim().isEmpty()) {
            return "created_at";
        }
        
        String trimmedSort = sort.trim();
        
        if (!ALLOWED_SORT_COLUMNS.contains(trimmedSort)) {
            throw new IllegalArgumentException("Invalid sort column: " + trimmedSort);
        }
        
        return trimmedSort;
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
The fix validates the `sort` parameter against a whitelist of allowed column names before it reaches the mapper. MyBatis's `${}` syntax performs string interpolation and cannot use parameterized binding for column names (which must be identifiers, not string values). Therefore, validation is the necessary defense.

The `validateSortColumn()` method in `InvoiceService`:
1. Returns a safe default ("created_at") if sort is null or empty
2. Trims whitespace from the input
3. Checks the trimmed value against `ALLOWED_SORT_COLUMNS`, a hardcoded set of valid column names
4. Throws `IllegalArgumentException` if the value is not in the whitelist

This whitelist-based validation ensures that only known, safe column names can reach the SQL query, preventing SQL injection even though the mapper continues to use `${}` interpolation. The validation occurs at the service layer, which is the appropriate place for business logic constraints.

The controller is simplified to pass the sort parameter directly to the service, which handles all validation logic.
