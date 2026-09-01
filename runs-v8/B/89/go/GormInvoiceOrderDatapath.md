## Verdict

exploitable

## Source

The `sort` parameter in the `Export` method signature (line 20) is passed directly from the caller without validation. It originates as untrusted user input.

## Fix

**Vulnerable code (line 24):**

```go
Order(sort).
```

**Fixed code:**

```go
// Allowlist of permitted sort columns to prevent injection
allowedSortColumns := map[string]string{
	"id":          "id",
	"account_id":  "account_id",
	"status":      "status",
	"total_cents": "total_cents",
}

sortColumn, ok := allowedSortColumns[sort]
if !ok {
	return fmt.Errorf("invalid sort column: %s", sort)
}

return r.DB.WithContext(ctx).
	Where("account_id = ? AND status = ?", accountID, status).
	Order(sortColumn).
	Find(&invoices).Error
```

(Add `"fmt"` to imports if not already present.)

## Explanation

The original code passes the untrusted `sort` parameter directly to GORM's `Order()` method, which does not escape SQL identifiers. An attacker can inject arbitrary SQL, such as `id; DROP TABLE invoices;--` to manipulate the query or execute destructive operations. The fix validates the `sort` parameter against an allowlist of permitted column names before use. Only when the input matches an allowlist entry is the canonical value from the allowlist used in the `Order()` call. This follows the principle that SQL identifiers cannot be parameterized and must be validated against a fixed set of safe values.

## Behaviour changes

- The function now returns an error (`fmt.Errorf`) if `sort` does not match an allowlisted column. Previously it would pass the untrusted value to `Order()` and execute the malicious query.
- An extra map allocation occurs on each call to build the allowlist. This can be optimized by moving the map to a package-level or receiver-level variable if performance is critical.
