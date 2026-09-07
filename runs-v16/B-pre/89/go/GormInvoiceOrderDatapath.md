## Verdict

Exploitable SQL injection through unvalidated ORDER BY clause.

## Source

Line 8 in invoice_handler.go: `sort := r.URL.Query().Get("sort")` — attacker-controlled query parameter flows through the call chain without validation.

## Fix

In invoice_repository.go, replace line 24 with allowlist validation before passing the sort value to `.Order()`:

```go
func (r *InvoiceRepository) Export(ctx context.Context, accountID string, status string, sort string) error {
	var invoices []Invoice
	
	// Allowlist of valid sort columns and directions
	validSorts := map[string]string{
		"id":           "id",
		"id_asc":       "id ASC",
		"id_desc":      "id DESC",
		"created":      "created_at",
		"created_asc":  "created_at ASC",
		"created_desc": "created_at DESC",
		"total":        "total_cents",
		"total_asc":    "total_cents ASC",
		"total_desc":   "total_cents DESC",
	}
	
	// Default to "id ASC" if sort is missing or invalid
	sortClause := "id ASC"
	if validSort, exists := validSorts[sort]; exists {
		sortClause = validSort
	}
	
	return r.DB.WithContext(ctx).
		Where("account_id = ? AND status = ?", accountID, status).
		Order(sortClause).
		Find(&invoices).Error
}
```

## Explanation

The vulnerability exists because GORM's `.Order()` method does not escape or parameterize its argument; it is concatenated directly into the SQL query. The `sort` parameter originates from user input (`r.URL.Query().Get("sort")`) and flows through the service layer to the repository without validation.

SQL identifiers like ORDER BY columns and sort directions cannot be parameterized in `database/sql` or GORM; they must be validated against an allowlist of permitted values before use. The fix defines a map of safe sort options and looks up the user's input against it. If the input matches, the corresponding canonical value from the map is used in the query; otherwise, a secure default is applied. The original untrusted input is never passed to `.Order()`.

## Behaviour changes

- Requests with an unrecognized or missing `sort` parameter now default to ordering by `id ASC` instead of using the raw input.
- Legitimate sort requests matching the allowlist work as before.
- Malicious payloads such as `sort=1 OR 1=1--` are rejected and treated as invalid, resulting in the default sort.
