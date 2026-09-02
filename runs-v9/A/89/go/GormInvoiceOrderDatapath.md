## Verdict

Confirmed. SQL injection via an attacker-controlled `ORDER BY` clause.

## Source

`sort := r.URL.Query().Get("sort")` in `InvoiceHandler` (invoice_handler.go, line 9). This value flows unmodified through `InvoiceService.ExportInvoices` (invoice_service.go, line 9-10) into `InvoiceRepository.Export` (invoice_repository.go, line 20), where it reaches the sink.

## Fix

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

// sortColumns maps the API's public sort keys to trusted column names.
// Only keys present in this map may reach the generated SQL.
var sortColumns = map[string]string{
	"id":     "id",
	"status": "status",
	"total":  "total_cents",
	"":       "id", // default when no sort is requested
}

func (r *InvoiceRepository) Export(ctx context.Context, accountID string, status string, sort string) error {
	column, ok := sortColumns[sort]
	if !ok {
		return fmt.Errorf("invalid sort field: %q", sort)
	}

	var invoices []Invoice
	return r.DB.WithContext(ctx).
		Where("account_id = ? AND status = ?", accountID, status).
		Order(column).
		Find(&invoices).Error
}
```

If callers also need to control direction (ascending/descending), take a separate `direction` parameter, validate it against a fixed set (`"asc"` or `"desc"`, case-insensitive), and append it to the trusted `column` string yourself - never interpolate a caller-supplied direction token directly.

## Explanation

GORM's `Order()` method (and `Where`/`Group` when given a raw string) inserts the string argument directly into the generated SQL statement; it is not parameterized the way `?` placeholders are. The handler reads `sort` straight from the `sort` query parameter and passes it through the service layer to `Order(sort)` with no validation at any hop, so a request like `?sort=1;DROP TABLE invoices;--` or `?sort=(SELECT ...)` is placed verbatim into the `ORDER BY` clause and executed as part of the query.

The fix replaces the raw pass-through with an allowlist that maps a small, fixed set of public sort keys to the actual trusted column identifiers. Only a value already present in the map can produce SQL, so no attacker-supplied string is ever concatenated into the statement; an unrecognized key is rejected with an error rather than silently defaulting, which also surfaces bad client input instead of masking it. Column names cannot be bound as query parameters (`?` placeholders only work for values, not identifiers), so an allowlist - rather than escaping or a denylist of dangerous keywords - is the correct primary defense for this class of sink.
