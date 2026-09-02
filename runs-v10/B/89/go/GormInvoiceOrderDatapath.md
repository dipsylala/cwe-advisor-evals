## Verdict

Exploitable

## Source

The `sort` parameter originates from untrusted user input via HTTP query parameter in invoice_handler.go line 9: `sort := r.URL.Query().Get("sort")`. This value flows through the service layer (invoice_service.go line 10) to the repository (invoice_repository.go line 20-26) without validation.

## Fix

**Vulnerable code (invoice_repository.go, line 24):**
```go
Order(sort).
```

**Fixed code:**
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

// allowedSortColumns maps user-provided sort strings to safe SQL identifiers.
// This prevents SQL injection by constraining Order() input to a fixed whitelist.
var allowedSortColumns = map[string]string{
	"id":           "id",
	"id_asc":       "id asc",
	"id_desc":      "id desc",
	"created_at":   "created_at",
	"created_asc":  "created_at asc",
	"created_desc": "created_at desc",
	"status":       "status",
	"status_asc":   "status asc",
	"status_desc":  "status desc",
	"total_cents":  "total_cents",
	"total_asc":    "total_cents asc",
	"total_desc":   "total_cents desc",
}

func (r *InvoiceRepository) Export(ctx context.Context, accountID string, status string, sort string) error {
	var invoices []Invoice
	
	// Break taint: validate sort parameter against allowlist and use only the canonical value
	validatedSort, ok := allowedSortColumns[sort]
	if !ok {
		// Default to id ascending for unknown sort values
		validatedSort = "id"
	}
	
	return r.DB.WithContext(ctx).
		Where("account_id = ? AND status = ?", accountID, status).
		Order(validatedSort).
		Find(&invoices).Error
}
```

## Explanation

The vulnerability exists because GORM's `Order()` method does not parameterize or escape its input—it interpolates the argument directly into the SQL ORDER BY clause. SQL identifiers (column names, sort direction) cannot be bound as query parameters in SQL, so the standard parameterization defense that protects `Where()` does not apply here. The fix implements allowlist validation: the user-supplied sort string is looked up in a `map[string]string` that contains only approved column-identifier combinations, and only the canonical mapped value is passed to `Order()`. Any sort value not in the allowlist defaults to a safe identifier ("id"), preventing SQL injection while maintaining functional behavior for valid inputs. The allowlist constrains input to exactly the columns and directions the application intends to expose, ensuring no attacker-controlled SQL is evaluated.

## Behaviour changes

- When the `sort` parameter matches an allowlist entry, behavior is identical to the original code—the same SQL ordering is applied.
- When the `sort` parameter does not match any allowlist entry, the query now defaults to ordering by `id` ascending instead of using the raw, unvalidated sort string. This is a change from the original behavior (which would have attempted to use the invalid value), but it prevents SQL injection and is the correct security-first default. Callers who require strict rejection of invalid sort values should either validate sort before calling `Export()`, or this method should return an error for disallowed sort strings (which would require a signature change to `error` handling).
