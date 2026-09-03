## Verdict

Exploitable.

## Source

User-supplied `sort` parameter from `InvoiceController.listInvoices()` (line 12) flows through `InvoiceService.listInvoices()` to `InvoiceMapper.findForTenant()` without validation.

## Fix

**Vulnerable code:**

```java
@Select("SELECT id, status, total_cents FROM invoices WHERE tenant_id = #{tenantId} ORDER BY ${sort}")
List<InvoiceRow> findForTenant(@Param("tenantId") String tenantId, @Param("sort") String sort);
```

**Fixed code (InvoiceMapper.java):**

```java
enum SortColumn {
    ID("id"),
    STATUS("status"),
    TOTAL_CENTS("total_cents"),
    CREATED_AT("created_at");

    private final String columnName;

    SortColumn(String columnName) {
        this.columnName = columnName;
    }

    public String getColumnName() {
        return columnName;
    }

    static SortColumn fromString(String value) {
        for (SortColumn col : SortColumn.values()) {
            if (col.name().equalsIgnoreCase(value) || col.columnName.equalsIgnoreCase(value)) {
                return col;
            }
        }
        return CREATED_AT; // default
    }
}

@Select("SELECT id, status, total_cents FROM invoices WHERE tenant_id = #{tenantId} ORDER BY ${sort}")
List<InvoiceRow> findForTenant(@Param("tenantId") String tenantId, @Param("sort") String sort);
```

**Fixed code (InvoiceService.java):**

```java
public List<InvoiceRow> listInvoices(String tenantId, String sort) {
    SortColumn sortCol = SortColumn.fromString(sort != null ? sort : "created_at");
    return mapper.findForTenant(tenantId, sortCol.getColumnName());
}
```

## Explanation

The original code uses MyBatis's `${}` placeholder for the sort parameter, which performs raw text substitution instead of parameterization. This allows an attacker to inject SQL fragments through the sort parameter (e.g., `id; DROP TABLE invoices; --`). The fix implements an allowlist of permitted sort columns as an enum, validates the user input against this allowlist in the service layer, and passes only the server-controlled column name to the mapper. This ensures the SQL query can only reference known, safe column identifiers, preventing SQL injection. The enum's `fromString()` method returns a sensible default (`CREATED_AT`) for invalid input rather than rejecting the request, preserving usability.

## Behaviour changes

The service layer now validates the sort parameter and coerces it to a known column. Invalid sort values that do not match any allowed column name default to `CREATED_AT` instead of being passed directly to the SQL query. This is a functional change that improves safety: user requests with typos or malicious payloads now sort by a safe default rather than attempting to inject SQL. The query result set remains identical for all valid sort column names; only invalid/injection attempts behave differently.
