## Verdict

Confirmed SQL injection via unvalidated `ORDER BY` clause. The `sort` parameter flows directly from the function argument to GORM's `Order()` method without validation or parameterization, allowing an attacker to inject arbitrary SQL.

## Source

- **Parameter:** `sort` (line 20, function signature)
- **Type:** String, untrusted external input
- **Source location:** Function parameter `Export(..., sort string, ...)`

## Fix

Replace the unvalidated `sort` parameter with an allowlist-validated value. GORM's `Order()` method does not support parameterized identifiers or clauses, so all sort expressions must be validated against a whitelist before use.

**Vulnerable code:**

```go
func (r *InvoiceRepository) Export(ctx context.Context, accountID string, status string, sort string) error {
	var invoices []Invoice
	return r.DB.WithContext(ctx).
		Where("account_id = ? AND status = ?", accountID, status).
		Order(sort).  // SQL INJECTION: sort is not validated
		Find(&invoices).Error
}
```

**Fixed code:**

```go
// Define allowlist of safe sort expressions
var allowedSorts = map[string]string{
	"id_asc":         "id ASC",
	"id_desc":        "id DESC",
	"account_id_asc": "account_id ASC",
	"account_id_desc": "account_id DESC",
	"status_asc":     "status ASC",
	"status_desc":    "status DESC",
	"total_asc":      "total_cents ASC",
	"total_desc":     "total_cents DESC",
}

func (r *InvoiceRepository) Export(ctx context.Context, accountID string, status string, sort string) error {
	var invoices []Invoice
	
	// Validate sort against allowlist, default to "id ASC" if invalid
	orderClause, ok := allowedSorts[sort]
	if !ok {
		return fmt.Errorf("invalid sort parameter: %q", sort)
	}
	
	return r.DB.WithContext(ctx).
		Where("account_id = ? AND status = ?", accountID, status).
		Order(orderClause).
		Find(&invoices).Error
}
```

## Explanation

GORM's `Order()` method accepts a string that is directly interpolated into the SQL `ORDER BY` clause without escaping. Unlike `Where()`, which supports parameterized placeholders (`?`), `Order()` cannot bind its argument as a data value because SQL identifiers (column names) and keywords (ASC/DESC directions) are not values and cannot be parameterized.

The fix defines a `map[string]string` allowlist that maps user-supplied sort keys to safe SQL expressions. The incoming `sort` parameter is validated against this allowlist; only if a match exists is the canonical, hardcoded value used in the query. This ensures the attacker cannot inject SQL syntax—they can only select from the predefined set of allowed sort columns and directions.

The `fmt.Errorf` return maintains error handling and prevents silent failures; invalid inputs are rejected explicitly rather than defaulting to an unsafe fallback.

## Behaviour changes

- **Input validation:** The `sort` parameter is now validated against a fixed allowlist; invalid values are rejected with an error instead of being passed through.
- **Return value:** The function may now return an error if `sort` does not match any allowlist entry (e.g., `"invalid sort parameter: 'id; DROP TABLE invoices'"`).
- **Query execution:** Only pre-approved sort expressions are sent to the database; attacker-controlled SQL syntax cannot reach the `ORDER BY` clause.
- **Performance:** No measurable change; the allowlist lookup is O(1).
- **Backward compatibility:** Callers must pass one of the allowlist keys. If the previous API accepted arbitrary sort strings, calling code will need to map user input to these keys.
