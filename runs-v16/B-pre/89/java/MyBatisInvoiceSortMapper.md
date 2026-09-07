## Verdict

Exploitable. An attacker can inject arbitrary SQL via the `sort` parameter because MyBatis `${}` substitution (line 8 of InvoiceMapper.java) directly interpolates untrusted input into the query string without parameterization.

## Source

`InvoiceController.listInvoices(String tenantId, String sort)` receives the sort parameter from an external request. The parameter is passed through `InvoiceService.listInvoices()` unchanged and reaches `InvoiceMapper.findForTenant()` at line 8.

## Fix

**Vulnerable code (InvoiceMapper.java line 8):**
```java
@Select("SELECT id, status, total_cents FROM invoices WHERE tenant_id = #{tenantId} ORDER BY ${sort}")
List<InvoiceRow> findForTenant(@Param("tenantId") String tenantId, @Param("sort") String sort);
```

**Fixed code (InvoiceMapper.java - add validation before query execution):**

Option 1 - Validate using a static allowlist (recommended for the mapper):

```java
package cases.mybatis;

import java.util.List;
import java.util.Set;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

public interface InvoiceMapper {
    Set<String> ALLOWED_SORT_COLUMNS = Set.of("id", "status", "total_cents", "created_at", "updated_at");

    @Select("SELECT id, status, total_cents FROM invoices WHERE tenant_id = #{tenantId} ORDER BY ${sort}")
    List<InvoiceRow> findForTenant(@Param("tenantId") String tenantId, @Param("sort") String sort);

    default List<InvoiceRow> findForTenantSafe(String tenantId, String sort) {
        if (!ALLOWED_SORT_COLUMNS.contains(sort)) {
            throw new IllegalArgumentException("Invalid sort column: " + sort);
        }
        return findForTenant(tenantId, sort);
    }
}

record InvoiceRow(String id, String status, long totalCents) {}
```

Option 2 - Validate at the controller entry point (cleaner separation of concerns):

**InvoiceController.java:**
```java
package cases.mybatis;

import java.util.List;
import java.util.Set;

public class InvoiceController {
    private final InvoiceService service;
    private static final Set<String> ALLOWED_SORT_COLUMNS = 
        Set.of("id", "status", "total_cents", "created_at", "updated_at");

    public InvoiceController(InvoiceService service) {
        this.service = service;
    }

    public List<InvoiceRow> listInvoices(String tenantId, String sort) {
        String validatedSort = sort == null ? "created_at" : sort;
        
        if (!ALLOWED_SORT_COLUMNS.contains(validatedSort)) {
            throw new IllegalArgumentException("Invalid sort column: " + validatedSort);
        }
        
        return service.listInvoices(tenantId, validatedSort);
    }
}
```

**InvoiceMapper.java (unchanged):**
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

## Explanation

The vulnerability exists because MyBatis `${}` substitution performs raw text replacement, directly interpolating the `sort` parameter into the SQL query. Unlike `#{}`, which generates a parameterized placeholder, `${}` is intended only for dynamic identifiers (column names, table names) that cannot be parameterized. The current code treats an external input as if it were a trusted identifier, allowing attackers to inject SQL operators, subqueries, or commands.

The fix applies an allowlist at the entry point (InvoiceController) that validates the sort parameter against a fixed set of permitted column names (`id`, `status`, `total_cents`, `created_at`, `updated_at`). Only values matching the allowlist are passed downstream. This ensures that by the time the `sort` parameter reaches the MyBatis mapper, it is guaranteed to be one of the expected column identifiers, eliminating the injection surface. The allowlist approach treats the dynamic identifier as a key into a server-controlled set of permitted names, not as user-supplied input, which aligns with the CWE-89 guidance for handling non-parameterizable query elements.

## Behaviour changes

**InvoiceController behavior changes:**
1. An `IllegalArgumentException` is now thrown if the sort parameter does not match the allowlist (previously any string was accepted). This prevents malicious input from reaching the database.
2. The null-check default (`"created_at"`) is applied before validation, ensuring the default value is also validated against the allowlist.

**Why these changes are necessary and safe:**
- The exception signals an invalid request to the caller, which is the correct HTTP 400-like semantics for rejecting untrusted input. The previous behavior silently accepted any string and passed it to the database.
- The allowlist includes all reasonable sort columns for an invoice query (id, status, total_cents, created_at, updated_at). If additional columns are needed in the future, they must be explicitly added to the allowlist, maintaining the principle of least privilege.
- The sink contract (MyBatis `${}` substitution) is unchanged: it still receives a string to interpolate directly into the ORDER BY clause. The difference is that the string is now guaranteed to be a safe identifier, not untrusted input.
