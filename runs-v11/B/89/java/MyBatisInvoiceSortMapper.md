## Verdict

Exploitable. The `sort` parameter flows from user input in `InvoiceController` through `InvoiceService` to the MyBatis mapper, where it is directly substituted into the SQL query using `${}` without validation. An attacker can inject arbitrary SQL through this parameter.

## Source

User input enters via `InvoiceController.listInvoices(String tenantId, String sort)` parameter (line 12), flows through `InvoiceService.listInvoices()` (line 13), and reaches the mapper's `findForTenant()` method.

## Fix

**Vulnerable code (InvoiceMapper.java, line 8):**
```java
@Select("SELECT id, status, total_cents FROM invoices WHERE tenant_id = #{tenantId} ORDER BY ${sort}")
List<InvoiceRow> findForTenant(@Param("tenantId") String tenantId, @Param("sort") String sort);
```

**Fixed code - Option 1: Enum-based validation (Recommended)**

Add an enum for allowed sort columns:
```java
public enum InvoiceSortColumn {
    ID("id"),
    STATUS("status"),
    TOTAL_CENTS("total_cents"),
    CREATED_AT("created_at");

    private final String sqlColumn;

    InvoiceSortColumn(String sqlColumn) {
        this.sqlColumn = sqlColumn;
    }

    public String getSqlColumn() {
        return sqlColumn;
    }

    public static InvoiceSortColumn fromString(String value) {
        if (value == null) {
            return CREATED_AT;  // default
        }
        for (InvoiceSortColumn col : values()) {
            if (col.name().equalsIgnoreCase(value)) {
                return col;
            }
        }
        throw new IllegalArgumentException("Invalid sort column: " + value);
    }
}
```

Update `InvoiceController`:
```java
public List<InvoiceRow> listInvoices(String tenantId, String sort) {
    InvoiceSortColumn sortColumn = InvoiceSortColumn.fromString(sort);
    return service.listInvoices(tenantId, sortColumn.getSqlColumn());
}
```

Update `InvoiceMapper`:
```java
@Select("SELECT id, status, total_cents FROM invoices WHERE tenant_id = #{tenantId} ORDER BY ${sort}")
List<InvoiceRow> findForTenant(@Param("tenantId") String tenantId, @Param("sort") String sort);
```

The mapper method signature remains the same; the validation and mapping happen in the controller/service layer.

**Fixed code - Option 2: Direct validation in Service**

Update `InvoiceService`:
```java
private static final Set<String> ALLOWED_SORT_COLUMNS = Set.of("id", "status", "total_cents", "created_at");

public List<InvoiceRow> listInvoices(String tenantId, String sort) {
    String safeSortColumn = ALLOWED_SORT_COLUMNS.contains(sort) ? sort : "created_at";
    return mapper.findForTenant(tenantId, safeSortColumn);
}
```

The mapper remains unchanged.

## Explanation

MyBatis `${}` performs raw text substitution and cannot be parameterized for column/table names (unlike `#{}` which is restricted to value positions). The fix validates the sort parameter against an allowlist of permitted columns before passing it to the query. Only values that match an entry in the allowlist are used; the canonical value from the list (not the original user input) is substituted into the query. This prevents injection because the attacker's input is never allowed to reach the SQL string—it is either mapped to a safe constant or rejected. The controller's existing default fallback to "created_at" is preserved as the security default when an invalid sort value is provided.

## Behaviour changes

**Option 1 (Enum):**
- Throws `IllegalArgumentException` if an invalid sort column is provided instead of silently defaulting
- Requires case-insensitive matching against enum names (not column names) on input; consider user-facing error handling
- Centralizes allowed sort columns in one enum definition for easier auditing and maintenance

**Option 2 (Set-based validation):**
- Silently defaults to "created_at" for invalid sort values (matches the existing controller behavior more closely)
- Fewer dependencies; simpler to implement in a legacy codebase
- Validation happens at the service layer; ensure the same validation is applied at all entry points to the mapper

Both options preserve the return type, parameter types, and the MyBatis mapper signature. The `#{tenantId}` parameterization remains intact and continues to protect that value.
