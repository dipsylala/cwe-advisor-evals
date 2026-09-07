## Verdict

Exploitable. The `sort` parameter originates from user input (`InvoiceController.listInvoices()`) and flows directly to line 8 of `InvoiceMapper.java`, where `${sort}` performs raw text substitution in the SQL query. An attacker can inject arbitrary SQL by providing malicious input such as `"created_at); DROP TABLE invoices; --"`.

## Source

- **Data source**: `InvoiceController.listInvoices(String tenantId, String sort)` - the `sort` parameter is untrusted user input, typically from a web request parameter
- **Data flow**: `sort` → `InvoiceService.listInvoices()` → `InvoiceMapper.findForTenant()` → line 8, the `@Select` annotation
- **Sink**: `InvoiceMapper.java`, line 8: `@Select("SELECT id, status, total_cents FROM invoices WHERE tenant_id = #{tenantId} ORDER BY ${sort}")`
- **Vulnerability mechanism**: MyBatis `${}` performs raw string substitution, unlike `#{}` which generates a `PreparedStatement` placeholder. The `ORDER BY` clause requires a column identifier (not a bound parameter), so `#{}` cannot be used here directly, but the untrusted value must not be concatenated raw.

## Fix

**Vulnerable code** (InvoiceController.java):
```java
public List<InvoiceRow> listInvoices(String tenantId, String sort) {
    return service.listInvoices(tenantId, sort == null ? "created_at" : sort);
}
```

**Fixed code** (InvoiceController.java):
```java
private static final Set<String> ALLOWED_SORT_COLUMNS = Set.of(
    "id", "status", "total_cents", "created_at"
);

public List<InvoiceRow> listInvoices(String tenantId, String sort) {
    String validSort = "created_at";  // Default
    if (sort != null && ALLOWED_SORT_COLUMNS.contains(sort)) {
        validSort = sort;
    }
    return service.listInvoices(tenantId, validSort);
}
```

The mapper itself does not change - it continues to use `${sort}`, but now only receives allowlisted column names:

```java
@Select("SELECT id, status, total_cents FROM invoices WHERE tenant_id = #{tenantId} ORDER BY ${sort}")
List<InvoiceRow> findForTenant(@Param("tenantId") String tenantId, @Param("sort") String sort);
```

## Explanation

The fix introduces an allowlist of permitted column names in the controller. Before passing the `sort` parameter downstream, it is validated against this set. If the value matches an allowlisted name, that constant is used; otherwise, the default `"created_at"` is substituted. This ensures that only safe, server-controlled identifiers reach the MyBatis mapper, preventing SQL injection via the `ORDER BY` clause. The `${}` substitution in the mapper now always receives a literal column name, not untrusted user input. The `tenantId` parameter remains protected by `#{}` parameterization, which was already safe.

## Behaviour changes

1. **Invalid sort columns are rejected silently**: If a caller provides a `sort` value not in the allowlist, it is replaced with the default `"created_at"` rather than passed through. This prevents injection but changes behavior - a request with an invalid sort column no longer fails with an error; instead, the default is applied. This is intentional and desired: the attacker cannot control the outcome, and the API degrades gracefully.

2. **ALLOWED_SORT_COLUMNS constant**: A new private static field is introduced. It contains the set of column names the application permits for dynamic sorting. This is a server-controlled constant and poses no security risk; it documents the permitted values in one place.

No changes to method signatures, return types, or error handling. The query result is identical for all valid inputs. The service and mapper layers require no changes.
