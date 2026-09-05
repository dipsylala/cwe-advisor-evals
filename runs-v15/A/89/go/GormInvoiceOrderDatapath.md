## Verdict

The `sort` parameter from user input (line 9 of invoice_handler.go) is passed directly to GORM's `Order()` method at line 24 of invoice_repository.go without validation. The `Order()` method accepts raw SQL expressions, allowing an attacker to inject arbitrary SQL clauses. This is a SQL injection vulnerability.

## Source

The vulnerable code path:
1. **invoice_handler.go:9** — User input: `sort := r.URL.Query().Get("sort")`
2. **invoice_handler.go:11** — Pass to service: `service.ExportInvoices(r.Context(), accountID, status, sort)`
3. **invoice_service.go:10** — Forward to repository: `s.Repository.Export(ctx, accountID, status, sort)`
4. **invoice_repository.go:24** — SQL injection sink: `.Order(sort)`

The `sort` parameter is attacker-controlled and used directly in a SQL expression without validation.

## Fix

Replace the unsanitized `Order()` call with an allowlist of valid column names and sort directions:

```go
package gorminvoice

import (
	"context"
	"fmt"
	"strings"

	"gorm.io/gorm"
)

type Invoice struct {
	ID         string
	AccountID  string
	Status     string
	TotalCents int64
}

type InvoiceRepository struct {
	DB *gorm.DB
}

func (r *InvoiceRepository) Export(ctx context.Context, accountID string, status string, sort string) error {
	var invoices []Invoice
	
	// Validate sort parameter against allowlist
	orderClause := buildSafeOrderClause(sort)
	
	query := r.DB.WithContext(ctx).
		Where("account_id = ? AND status = ?", accountID, status)
	
	if orderClause != "" {
		query = query.Order(orderClause)
	}
	
	return query.Find(&invoices).Error
}

// buildSafeOrderClause validates the sort parameter against an allowlist
// and returns a safe SQL clause or empty string if invalid
func buildSafeOrderClause(sort string) string {
	// Allowlist of safe column names
	allowedColumns := map[string]bool{
		"id":          true,
		"account_id":  true,
		"status":      true,
		"total_cents": true,
	}
	
	if sort == "" {
		return ""
	}
	
	// Parse "column direction" format (e.g., "total_cents desc")
	parts := strings.Fields(strings.TrimSpace(sort))
	if len(parts) == 0 || len(parts) > 2 {
		return ""
	}
	
	column := strings.ToLower(parts[0])
	
	// Verify column is in allowlist
	if !allowedColumns[column] {
		return ""
	}
	
	// Default to ASC if no direction specified
	direction := "asc"
	if len(parts) == 2 {
		direction = strings.ToLower(parts[1])
		if direction != "asc" && direction != "desc" {
			return ""
		}
	}
	
	return fmt.Sprintf("%s %s", column, direction)
}
```

## Explanation

The remediation uses an allowlist approach to validate the `sort` parameter:

1. **Define allowed columns**: Only column names present in the `Invoice` struct are accepted (`id`, `account_id`, `status`, `total_cents`).

2. **Parse and validate input**: Split the sort parameter into column and direction components. Only accept empty strings, a single column name, or a column name followed by `asc` or `desc`.

3. **Reconstruct safe clause**: After validation, rebuild the `ORDER BY` clause using `fmt.Sprintf()` with the validated column and direction, ensuring the result contains only safe values.

4. **Conditional query construction**: Pass the validated clause to `Order()` only if it passes validation; if invalid input is provided, the query runs without sorting rather than executing attacker-supplied SQL.

This approach:
- Prevents SQL injection by rejecting any sort parameter that doesn't match the allowlist
- Maintains usability by accepting common sort syntax (e.g., "total_cents desc")
- Defaults to ascending order if no direction is specified
- Returns an empty order clause for invalid input instead of executing it
