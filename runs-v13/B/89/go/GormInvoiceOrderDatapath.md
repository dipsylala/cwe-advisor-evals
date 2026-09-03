## Verdict

Exploitable

## Source

The `sort` parameter in the function signature originates from untrusted user input: in `invoice_handler.go` line 9, it is extracted directly from the URL query string via `r.URL.Query().Get("sort")`, then passed through the call chain unchanged to the repository.

## Fix

**Vulnerable Code:**
```go
func (r *InvoiceRepository) Export(ctx context.Context, accountID string, status string, sort string) error {
	var invoices []Invoice
	return r.DB.WithContext(ctx).
		Where("account_id = ? AND status = ?", accountID, status).
		Order(sort).  // SQL injection: sort parameter is concatenated directly
		Find(&invoices).Error
}
```

**Fixed Code:**
```go
func (r *InvoiceRepository) Export(ctx context.Context, accountID string, status string, sort string) error {
	var invoices []Invoice

	// Allowlist of permitted sort columns and directions
	permittedSorts := map[string]string{
		"id_asc":          "id ASC",
		"id_desc":         "id DESC",
		"created_at_asc":  "created_at ASC",
		"created_at_desc": "created_at DESC",
	}

	// Validate and select sort value from allowlist
	sortValue, ok := permittedSorts[sort]
	if !ok {
		sortValue = "id ASC"
	}

	return r.DB.WithContext(ctx).
		Where("account_id = ? AND status = ?", accountID, status).
		Order(sortValue).
		Find(&invoices).Error
}
```

## Explanation

GORM's `Order()` method does not escape its string argument and directly interpolates it into the SQL query. The `sort` parameter cannot be bound as a parameter in SQL because it specifies query structure (the column and direction), not a data value. The fix implements allowlist validation: a map of permitted sort identifiers is defined, the user-supplied sort value is looked up against this map, and only the canonical value from the map is passed to `Order()`. If the user provides an invalid sort value (including empty string), the code defaults to a safe sort value `"id ASC"`. This ensures that any attacker-controlled input cannot alter the query structure, eliminating the SQL injection vector while maintaining query functionality.

## Behaviour changes

- If the `sort` parameter is not in the allowlist map (or is empty string), the query now defaults to sorting by `id ASC` instead of being passed to GORM as-is. Original behavior: GORM would receive the raw sort parameter and either apply it as-is or potentially error if the SQL syntax was invalid. New behavior: only whitelisted sort expressions are accepted, with a safe default. This is a security-motivated restriction on input acceptance, not a functional change to successful queries.
- The allowlist map is instantiated on every call to `Export()`. Moving it to a package-level or struct-level constant would reduce allocation overhead if this method is called frequently, but would not alter correctness.
