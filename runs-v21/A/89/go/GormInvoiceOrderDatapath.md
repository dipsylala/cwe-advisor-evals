## Verdict

Real SQL injection vulnerability. The `sort` parameter from the HTTP request is passed directly to GORM's `Order()` method without parameterization or validation, allowing attackers to inject arbitrary SQL.

## Source

The call chain:
1. `invoice_handler.go`: Line 9 reads `sort` from `r.URL.Query().Get("sort")` 
2. `invoice_service.go`: Line 10 passes `sort` to repository
3. `invoice_repository.go`: Line 24 uses `Order(sort)` with unsanitized input

## Fix

### File: invoice_repository.go

```go
package gorminvoice

import (
	"context"
	"regexp"
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

// isValidSort validates the sort parameter against a whitelist of column names and directions
func (r *InvoiceRepository) isValidSort(sort string) bool {
	if sort == "" {
		return true
	}

	// Allow only whitelisted column names with optional ASC/DESC direction
	re := regexp.MustCompile(`^(id|account_id|status|total_cents)\s*(asc|desc)?$`)
	return re.MatchString(strings.ToLower(sort))
}

func (r *InvoiceRepository) Export(ctx context.Context, accountID string, status string, sort string) error {
	var invoices []Invoice
	query := r.DB.WithContext(ctx).
		Where("account_id = ? AND status = ?", accountID, status)

	// Only apply sort if it passes validation
	if sort != "" && r.isValidSort(sort) {
		query = query.Order(sort)
	}

	return query.Find(&invoices).Error
}
```

## Explanation

The vulnerability exists because GORM's `Order()` method does not parameterize its argument—it constructs raw SQL from the string. Unlike the `Where()` method which uses `?` placeholders for safe parameterization, `Order()` interprets its input as a literal SQL fragment.

The fix adds a validation function that restricts the `sort` parameter to a strict allowlist of known column names (`id`, `account_id`, `status`, `total_cents`) with optional direction keywords (`asc`, `desc`). The regex enforces this allowlist, preventing attackers from injecting SQL operators, functions, or comments.

- If `sort` is empty, no ordering is applied (safe default)
- If `sort` matches the allowlist, it is safe to pass to `Order()`
- If `sort` does not match, it is silently ignored and default ordering is used

This approach preserves GORM's intended column name normalization while completely closing the injection vector.
