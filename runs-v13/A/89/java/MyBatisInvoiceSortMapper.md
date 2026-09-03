## Verdict
Confirmed SQL injection vulnerability via unvalidated `${sort}` parameter interpolation.

## Source
Line 8 in InvoiceMapper.java uses MyBatis string substitution syntax `${}` for the ORDER BY clause:
```java
@Select("SELECT id, status, total_cents FROM invoices WHERE tenant_id = #{tenantId} ORDER BY ${sort}")
```

This allows an attacker to inject arbitrary SQL by passing a malicious `sort` parameter (e.g., `"id) UNION SELECT ..."`), since `${}` directly interpolates the value into the query without parameterization or escaping.

## Fix
Replace the dynamic string substitution with an allowlist of valid sort expressions. Update the method signature to accept validated sort criteria:

```java
public interface InvoiceMapper {
    @Select("SELECT id, status, total_cents FROM invoices WHERE tenant_id = #{tenantId} ORDER BY id ASC")
    List<InvoiceRow> findForTenant(@Param("tenantId") String tenantId);

    @Select("SELECT id, status, total_cents FROM invoices WHERE tenant_id = #{tenantId} ORDER BY id DESC")
    List<InvoiceRow> findForTenantDescending(@Param("tenantId") String tenantId);

    @Select("SELECT id, status, total_cents FROM invoices WHERE tenant_id = #{tenantId} ORDER BY status ASC")
    List<InvoiceRow> findForTenantByStatus(@Param("tenantId") String tenantId);

    @Select("SELECT id, status, total_cents FROM invoices WHERE tenant_id = #{tenantId} ORDER BY total_cents DESC")
    List<InvoiceRow> findForTenantByAmount(@Param("tenantId") String tenantId);
}
```

Alternatively, if dynamic sorting is required, validate the sort parameter in the application before passing it to MyBatis, restricting it to a hardcoded set of safe column names and directions:

```java
public enum SortField {
    ID("id"), STATUS("status"), TOTAL("total_cents");
    private final String column;
    SortField(String column) { this.column = column; }
}

public enum SortDirection {
    ASC("ASC"), DESC("DESC");
    private final String direction;
    SortDirection(String direction) { this.direction = direction; }
}

// Validate and build safe sort expression
String validatedSort = sortField.column + " " + sortDirection.direction;
```

## Explanation
MyBatis provides two placeholder syntaxes: `#{}` (parameterized, safe) and `${}` (string substitution, unsafe). The `${sort}` parameter is interpolated directly into the SQL query string without sanitization, allowing SQL injection.

ORDER BY clauses cannot use standard parameter binding with `#{}` because SQL syntax requires the column name to be a literal identifier, not a placeholder bound as a string value. The proper remediation is to either:
1. Provide separate, hardcoded query methods for each allowed sort order (safest, no runtime logic)
2. Use application-level validation to restrict the sort parameter to an explicit allowlist of column names and directions, building a safe sort expression before passing to MyBatis
3. Use MyBatis dynamic SQL with `<if>` or `<choose>` blocks to conditionally build only whitelisted clauses

All approaches eliminate the SQL injection risk by ensuring ORDER BY never contains untrusted user input.
