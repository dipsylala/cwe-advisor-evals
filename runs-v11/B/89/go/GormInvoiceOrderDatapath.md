## Verdict

Exploitable. User-supplied input from the HTTP query parameter `sort` flows directly into GORM's `Order()` method without validation, allowing SQL injection through the ORDER BY clause.

## Source

- **Entry point**: `invoice_handler.go` line 9 - `sort := r.URL.Query().Get("sort")`
- **Data flow**: invoice_handler.go line 11 → invoice_service.go line 10 → invoice_repository.go line 24
- **Sink**: `invoice_repository.go` line 24 - `Order(sort)`

The `sort` query parameter is untrusted user input. It flows through the service layer to the repository, where it is passed directly to GORM's `Order()` method, which concatenates it into the SQL ORDER BY clause without escaping or parameterization.

## Fix

**Vulnerable code:**
```go
func (r *InvoiceRepository) Export(ctx context.Context, accountID string, status string, sort string) error {
	var invoices []Invoice
	return r.DB.WithContext(ctx).
		Where("account_id = ? AND status = ?", accountID, status).
		Order(sort).  // ← SQL injection: sort is untrusted and not validated
		Find(&invoices).Error
}
```

**Fixed code:**
```go
func (r *InvoiceRepository) Export(ctx context.Context, accountID string, status string, sort string) error {
	var invoices []Invoice
	
	// Allowlist of permitted sort columns
	allowedSorts := map[string]string{
		"id":          "id",
		"status":      "status",
		"total_cents": "total_cents",
	}
	
	// Validate sort parameter against allowlist
	sortColumn, ok := allowedSorts[sort]
	if !ok {
		sortColumn = "id" // Default to id if sort is invalid or missing
	}
	
	return r.DB.WithContext(ctx).
		Where("account_id = ? AND status = ?", accountID, status).
		Order(sortColumn).  // ← Use validated value only
		Find(&invoices).Error
}
```

## Explanation

The vulnerability occurs because GORM's `Order()` method does not parameterize or escape its string argument. SQL identifiers like column names and sort directions cannot be parameterized (only data values can be), so the safe pattern is allowlist validation: look up the user-supplied value in a map of known-safe identifiers and use only the resolved value from that map in the query. The fix creates a `allowedSorts` map containing all permitted sort columns, validates the incoming `sort` parameter against it, and uses only the whitelisted value in the `Order()` call. If the user provides an invalid sort value, it defaults to `"id"` rather than rejecting the request, preserving the query's ability to execute. This eliminates the injection vector while maintaining the sorting functionality.

## Behaviour changes

- Added a default sort column `"id"` when the user supplies an invalid or missing sort value. Original behavior: passed the untrusted input directly to Order(), which would either sort by that column (if it exists) or raise a database error (if it doesn't). New behavior: defaults to sorting by id rather than erroring, ensuring the query always succeeds. This is a usability improvement over potentially returning an error.
- Added initialization of the `allowedSorts` map with three permitted sort columns: id, status, total_cents. These are the safe columns available in the Invoice struct. The fix maintains the same return type and error contract as the original.
