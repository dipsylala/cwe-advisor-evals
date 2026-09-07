## Verdict

CONFIRMED - SQL injection via unvalidated ORDER BY clause in GORM query.

## Source

File: invoice_repository.go, line 24

The `sort` parameter from the HTTP request (originating from `invoice_handler.go`) flows untrusted into the GORM `Order()` method without validation. GORM does not escape identifiers passed to `Order()`, allowing an attacker to inject SQL fragments into the ORDER BY clause.

Call chain:
- `invoice_handler.go`: reads `sort` from `r.URL.Query().Get("sort")` (untrusted)
- `invoice_service.go`: passes to `Repository.Export()`
- `invoice_repository.go`, line 24: `.Order(sort)` - vulnerable sink

## Fix

### File: invoice_repository.go

```go
package gorminvoice

import (
	"context"

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
	
	// Allowlist of valid sort expressions to prevent SQL injection
	validSortExpressions := map[string]string{
		"id":               "id",
		"id_asc":           "id ASC",
		"id_desc":          "id DESC",
		"account_id":       "account_id",
		"account_id_asc":   "account_id ASC",
		"account_id_desc":  "account_id DESC",
		"status":           "status",
		"status_asc":       "status ASC",
		"status_desc":      "status DESC",
		"total_cents":      "total_cents",
		"total_cents_asc":  "total_cents ASC",
		"total_cents_desc": "total_cents DESC",
	}
	
	query := r.DB.WithContext(ctx).
		Where("account_id = ? AND status = ?", accountID, status)
	
	// Only apply Order clause if sort parameter matches allowlist
	if sortExpr, ok := validSortExpressions[sort]; ok {
		query = query.Order(sortExpr)
	}
	
	return query.Find(&invoices).Error
}
```

## Explanation

The vulnerability was that the `sort` parameter, derived from untrusted user input, was passed directly to GORM's `Order()` method. GORM's security documentation explicitly lists `Order` as a method that does not escape its input, making it a direct SQL injection sink for ORDER BY clauses.

The fix implements an allowlist of valid sort expressions. The map keys represent acceptable sort parameters that clients can request, and the map values are the safe SQL expressions passed to `Order()`. After receiving the `sort` parameter, the code looks it up in the allowlist. Only if the parameter exists in the map is the corresponding safe expression used in the query; otherwise, no ORDER clause is applied.

This approach:
- Prevents any SQL injection through the sort parameter
- Maintains the intended functionality for valid sort requests
- Follows the CWE-89 Go remediation guidance: validate identifiers against an allowlist before use
- Requires no changes to the handler or service layers (the fix is localized)
