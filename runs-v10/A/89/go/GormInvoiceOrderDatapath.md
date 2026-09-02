## Verdict
The vulnerability is confirmed. The `sort` parameter is user-controlled (from `r.URL.Query().Get("sort")` in the handler) and passed unsanitized to GORM's `Order()` method, which directly interpolates it into the SQL query without parameterization. This allows SQL injection.

## Source
The data flow:
- `InvoiceHandler` (line 9): reads `sort` from query parameter
- `InvoiceService.ExportInvoices` (line 10): passes `sort` to repository
- `InvoiceRepository.Export` (line 24): uses `Order(sort)` directly in query

## Fix
Validate the sort parameter against a whitelist of allowed columns and directions before passing it to GORM:

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

// allowedSortFields defines valid sort expressions to prevent SQL injection
var allowedSortFields = map[string]bool{
	"id asc":          true,
	"id desc":         true,
	"total_cents asc": true,
	"total_cents desc": true,
	"status asc":      true,
	"status desc":     true,
	"created_at asc":  true,
	"created_at desc": true,
}

func (r *InvoiceRepository) Export(ctx context.Context, accountID string, status string, sort string) error {
	var invoices []Invoice
	
	// Validate sort parameter against whitelist
	sortLower := strings.ToLower(strings.TrimSpace(sort))
	if sort != "" && !allowedSortFields[sortLower] {
		return fmt.Errorf("invalid sort parameter: %s", sort)
	}
	
	query := r.DB.WithContext(ctx).
		Where("account_id = ? AND status = ?", accountID, status)
	
	if sort != "" {
		query = query.Order(sortLower)
	}
	
	return query.Find(&invoices).Error
}
```

## Explanation
The `Order()` method in GORM does not support parameterized queries like `Where()` does. The fix uses a whitelist to validate that the sort parameter contains only allowed column names and sort directions (asc/desc). 

Key changes:
1. Define `allowedSortFields` map with all valid sort expressions (lowercase for case-insensitive matching)
2. Trim and convert the user input to lowercase, then check it against the whitelist
3. Return an error if the sort parameter is not in the whitelist
4. Only add the `Order()` clause if sort passes validation

This prevents attackers from injecting SQL while still allowing legitimate sort operations on designated columns.
