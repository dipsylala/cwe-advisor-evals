## Verdict

Confirmed SQL injection via unvalidated dynamic ORDER BY clause parameter in MyBatis annotation.

## Source

InvoiceMapper.java line 8:

```java
@Select("SELECT id, status, total_cents FROM invoices WHERE tenant_id = #{tenantId} ORDER BY ${sort}")
```

The `sort` parameter uses MyBatis `${}` string interpolation syntax without validation, allowing injection of arbitrary SQL. An attacker controlling the `sort` parameter could execute commands like `"id; DROP TABLE invoices; --"`.

## Fix

Apply a whitelist validation in the calling service layer before passing the sort value to the mapper. Create an enum or switch statement that restricts `sort` to known valid column names:

```java
public List<InvoiceRow> findInvoices(String tenantId, String sortParam) {
    String validSort = switch(sortParam) {
        case "id" -> "id";
        case "status" -> "status";
        case "total_cents" -> "total_cents";
        default -> "id"; // Safe default
    };
    return invoiceMapper.findForTenant(tenantId, validSort);
}
```

The mapper method remains unchanged; the fix occurs at the call site by validating the user-supplied `sortParam` before it reaches the `${}` placeholder.

## Explanation

ORDER BY column names cannot use parameterized placeholders (`#{}`) in standard SQL—identifiers must be string literals. Using `${}` for user input is dangerous because it performs direct string substitution. The fix validates the sort parameter against an allowlist of permitted column names in the application layer, ensuring only safe values reach the query. The switch statement acts as a gate that rejects any input not explicitly in the whitelist, preventing SQL injection regardless of attacker input.
