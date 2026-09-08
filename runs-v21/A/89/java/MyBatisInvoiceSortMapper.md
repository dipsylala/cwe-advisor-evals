## Verdict
Real vulnerability confirmed. The `sort` parameter flows from user input through the call chain to the MyBatis SQL query, where it is injected via `${sort}` string substitution, allowing SQL injection attacks.

## Source
The vulnerability originates in InvoiceController.listInvoices() which accepts a `sort` parameter from the caller. This parameter flows through InvoiceService.listInvoices() and is passed to InvoiceMapper.findForTenant(), where it is used in an unsafe MyBatis placeholder `${sort}` in the ORDER BY clause.

## Fix

### File: InvoiceService.java
```java
package cases.mybatis;

import java.util.List;
import java.util.Set;

public class InvoiceService {
    private final InvoiceMapper mapper;
    private static final Set<String> VALID_SORT_COLUMNS = Set.of(
        "id", "status", "total_cents", "created_at"
    );

    public InvoiceService(InvoiceMapper mapper) {
        this.mapper = mapper;
    }

    public List<InvoiceRow> listInvoices(String tenantId, String sort) {
        String validatedSort = validateSortColumn(sort);
        return mapper.findForTenant(tenantId, validatedSort);
    }

    private String validateSortColumn(String sort) {
        if (sort == null || sort.isEmpty()) {
            return "created_at";
        }
        if (VALID_SORT_COLUMNS.contains(sort)) {
            return sort;
        }
        return "created_at";
    }
}
```

## Explanation
MyBatis `${sort}` performs string substitution and cannot use parameterized binding for ORDER BY clauses. The fix implements an allowlist of valid column names (id, status, total_cents, created_at) in the service layer. The validateSortColumn() method ensures only whitelisted values reach the mapper; any invalid input defaults to "created_at". This prevents SQL injection by rejecting attacker-controlled malicious values before they reach the SQL template. The mapper and controller remain unchanged; the service layer becomes the enforcement point for input validation.
