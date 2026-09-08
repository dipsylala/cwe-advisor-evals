## Verdict

Exploitable. The `sort` parameter originates from untrusted user input (URL query parameter in `InvoiceHandler` line 9) and flows directly to GORM's `Order()` method at line 24 of `invoice_repository.go` without validation, allowing an attacker to inject arbitrary SQL into the ORDER BY clause.

## Source

`InvoiceHandler` receives the `sort` parameter from `r.URL.Query().Get("sort")` at line 9, passes it to `ExportInvoices()`, which passes it unchanged to `Repository.Export()`, and finally to `Order(sort)` at line 24 of `invoice_repository.go`.

## Fix

### File: invoice_repository.go

```go
package gorminvoice

import (
	"context"
	"fmt"

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

// permittedSortColumns maps user-provided sort values to safe SQL column identifiers
var permittedSortColumns = map[string]string{
	"id":          "id",
	"account_id":  "account_id",
	"status":      "status",
	"total_cents": "total_cents",
}

func (r *InvoiceRepository) Export(ctx context.Context, accountID string, status string, sort string) error {
	var invoices []Invoice

	// Validate sort parameter against allowlist to prevent SQL injection
	sortColumn, ok := permittedSortColumns[sort]
	if !ok {
		return fmt.Errorf("invalid sort column: %s", sort)
	}

	return r.DB.WithContext(ctx).
		Where("account_id = ? AND status = ?", accountID, status).
		Order(sortColumn).
		Find(&invoices).Error
}
```

## Explanation

SQL identifiers such as column names in ORDER BY clauses cannot be parameterized (GORM's `Order()` method does not support placeholders). The fix implements allowlist validation: the untrusted `sort` parameter is looked up in a `permittedSortColumns` map of permitted column names. Only the resolved value from the map is passed to `Order()`, ensuring the user input cannot reach the SQL query. If the sort value is not in the allowlist, the function returns an error instead of executing the unsafe query. This closes the injection path while preserving the intended functionality for valid sort columns.

## Behaviour changes

The function now returns an error with message `"invalid sort column: <value>"` if the `sort` parameter does not match a permitted column in the allowlist, whereas previously it would pass the untrusted value directly to `Order()` and execute it as SQL. This is a safety improvement: invalid sort requests are rejected rather than silently interpolated into the query. All valid sort columns continue to work as before. The set of permitted columns is defined in `permittedSortColumns` and can be extended without code changes if additional sortable columns are added to the Invoice schema in the future.
