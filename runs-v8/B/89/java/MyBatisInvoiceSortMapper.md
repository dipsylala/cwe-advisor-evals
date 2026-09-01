## Verdict

Exploitable. The `sort` parameter flows from user input through InvoiceController and InvoiceService to InvoiceMapper line 8, where it is substituted into the SQL `ORDER BY` clause via MyBatis's `${}` without validation.

## Source

User input enters at `InvoiceController.listInvoices(String tenantId, String sort)` line 12. The sort parameter is passed with a default value (`"created_at"` if null) but no validation against permitted sort columns. The value flows through `InvoiceService.listInvoices()` line 12 to `InvoiceMapper.findForTenant()` line 8.

## Fix

**Vulnerable code (InvoiceMapper.java line 8):**
```java
@Select("SELECT id, status, total_cents FROM invoices WHERE tenant_id = #{tenantId} ORDER BY ${sort}")
List<InvoiceRow> findForTenant(@Param("tenantId") String tenantId, @Param("sort") String sort);
```

**Vulnerable code (InvoiceService.java line 12–13):**
```java
public List<InvoiceRow> listInvoices(String tenantId, String sort) {
    return mapper.findForTenant(tenantId, sort);
}
```

**Fixed code (InvoiceService.java):**
```java
import java.util.Set;

public class InvoiceService {
    private final InvoiceMapper mapper;
    private static final Set<String> ALLOWED_SORT_COLUMNS = Set.of("created_at", "total_cents", "status");

    public InvoiceService(InvoiceMapper mapper) {
        this.mapper = mapper;
    }

    public List<InvoiceRow> listInvoices(String tenantId, String sort) {
        // Validate sort column against allowlist; use canonical value from allowlist
        String validatedSort = ALLOWED_SORT_COLUMNS.contains(sort) ? sort : "created_at";
        return mapper.findForTenant(tenantId, validatedSort);
    }
}
```

InvoiceMapper.java remains unchanged; the mapper continues to use `${sort}`, but the value it receives is now guaranteed to be one of the permitted sort columns.

## Explanation

The vulnerability is that `${sort}` in MyBatis's `@Select` annotation performs raw text substitution into the SQL string. While `${sort}` is MyBatis's intended mechanism for dynamic identifiers (table/column names that cannot be parameterized), it requires server-side validation to be safe. The fix adds a static allowlist of permitted sort columns (`created_at`, `total_cents`, `status`) and validates the incoming sort parameter against it. If the parameter matches an allowed column, that value is used; otherwise, the default `"created_at"` is substituted. This ensures only pre-approved column names reach the SQL query, preventing SQL injection via the ORDER BY clause. The parameterized `#{tenantId}` binding remains unchanged and continues to protect the WHERE clause.

## Behaviour changes

None. The fix preserves the original contract: it accepts a sort parameter and defaults to `"created_at"` if the input is invalid or null. The set of returned columns, result types, and query semantics remain identical. The only change is validation of the sort parameter against a server-controlled allowlist before query execution, which is a security boundary, not a functional change.
