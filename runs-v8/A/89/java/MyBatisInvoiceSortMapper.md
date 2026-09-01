## Verdict

**SQL Injection via String Substitution in ORDER BY Clause**

The `InvoiceMapper.findForTenant()` method at line 8 uses MyBatis string substitution (`${sort}`) for the ORDER BY clause. This allows an attacker to inject arbitrary SQL through the untrusted `sort` parameter that flows from the controller.

## Source

The `sort` parameter originates from the HTTP request handler in `InvoiceController.listInvoices()` and is passed through `InvoiceService.listInvoices()` directly to `InvoiceMapper.findForTenant()` without validation. In the mapper, it is interpolated into the SQL query using `${sort}` (line 8 of InvoiceMapper.java).

```
Controller → Service → Mapper → SQL Query
(untrusted)  (pass-through) (string substitution)
```

## Fix

Replace the unsafe string substitution with a whitelist of allowed sort column names and use conditional logic in the MyBatis mapper to safely construct the ORDER BY clause:

```java
// InvoiceMapper.java
public interface InvoiceMapper {
    @Select("<script>" +
            "SELECT id, status, total_cents FROM invoices " +
            "WHERE tenant_id = #{tenantId} " +
            "<choose>" +
            "  <when test=\"'id'.equals(sort) or 'status'.equals(sort) or 'total_cents'.equals(sort) or 'created_at'.equals(sort)\">" +
            "    ORDER BY ${sort}" +
            "  </when>" +
            "  <otherwise>" +
            "    ORDER BY created_at" +
            "  </otherwise>" +
            "</choose>" +
            "</script>")
    List<InvoiceRow> findForTenant(@Param("tenantId") String tenantId, @Param("sort") String sort);
}
```

Alternatively, perform validation in the service layer before calling the mapper:

```java
// InvoiceService.java
private static final Set<String> ALLOWED_SORT_COLUMNS = 
    Set.of("id", "status", "total_cents", "created_at");

public List<InvoiceRow> listInvoices(String tenantId, String sort) {
    // Validate sort parameter against whitelist
    String safeSortColumn = ALLOWED_SORT_COLUMNS.contains(sort) ? sort : "created_at";
    return mapper.findForTenant(tenantId, safeSortColumn);
}
```

Then update the mapper to use `${sort}` only after validation has occurred upstream:

```java
// InvoiceMapper.java (after validation in service)
@Select("SELECT id, status, total_cents FROM invoices WHERE tenant_id = #{tenantId} ORDER BY ${sort}")
List<InvoiceRow> findForTenant(@Param("tenantId") String tenantId, @Param("sort") String sort);
```

## Explanation

MyBatis uses two different mechanisms for parameter substitution:

- `#{name}` — Parameterized query placeholder; the value is bound as a prepared statement parameter and is always treated as a literal value. Safe for column names cannot be used here because the database will quote the value, treating it as a string literal instead of a column reference.
- `${name}` — String substitution in the SQL text before parsing. Unsafe when the value comes from untrusted input, as it allows SQL injection.

The ORDER BY clause requires a column name, which must be known at parse time. This means parameterized queries (`#{sort}`) cannot be used directly. The safe approach is to validate the sort parameter against a whitelist of allowed column names before using string substitution.

The controller provides a default value of `"created_at"` when sort is null, but this does not prevent SQL injection when a non-null value is provided. The validation must occur before the value is incorporated into the SQL query string.
