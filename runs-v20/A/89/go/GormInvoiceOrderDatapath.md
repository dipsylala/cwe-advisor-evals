## Verdict

Confirmed. `InvoiceRepository.Export` passes the caller-controlled `sort` value straight into GORM's `Order()` call. GORM's query builder parameterizes `Where` arguments, but `Order()` takes a raw SQL fragment and appends it to the generated `ORDER BY` clause verbatim - there is no placeholder for it. An attacker who controls `sort` controls part of the executed SQL statement (e.g. appending a subquery, `UNION`, or boolean/time-based payload after a real or fake column name), independent of the correctly parameterized `Where` filter.

## Source

- Untrusted input: `status := r.URL.Query().Get("status")` and `sort := r.URL.Query().Get("sort")` in `invoice_handler.go`, both taken from the request's query string.
- Data flow: `InvoiceHandler` -> `InvoiceService.ExportInvoices(ctx, accountID, status, sort)` in `invoice_service.go` -> `InvoiceRepository.Export(ctx, accountID, status, sort)` in `invoice_repository.go`, with no validation or transformation at any hop.
- Sink: `r.DB.WithContext(ctx).Where("account_id = ? AND status = ?", accountID, status).Order(sort).Find(&invoices)` in `invoice_repository.go` line 24 - `sort` reaches `Order()` unchanged and unvalidated.

## Fix

### File: invoice_repository.go
```go
package gorminvoice

import (
	"context"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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

// allowedInvoiceSortColumns maps API-facing sort keys to the real column
// names they may resolve to. A caller-supplied sort token that is not a key
// in this map can never reach the query as SQL text.
var allowedInvoiceSortColumns = map[string]string{
	"id":          "id",
	"status":      "status",
	"total_cents": "total_cents",
}

func (r *InvoiceRepository) Export(ctx context.Context, accountID string, status string, sort string) error {
	var invoices []Invoice

	column, desc := parseInvoiceSort(sort)

	return r.DB.WithContext(ctx).
		Where("account_id = ? AND status = ?", accountID, status).
		Order(clause.OrderByColumn{Column: clause.Column{Name: column}, Desc: desc}).
		Find(&invoices).Error
}

// parseInvoiceSort resolves a caller-supplied "field" or "field_desc" token
// to a known-safe column name and direction. Any token that does not match
// an allowed column exactly falls back to a fixed default rather than being
// passed through, so it never reaches the database as raw SQL.
func parseInvoiceSort(sort string) (column string, desc bool) {
	field := sort
	switch {
	case strings.HasSuffix(sort, "_desc"):
		field = strings.TrimSuffix(sort, "_desc")
		desc = true
	case strings.HasSuffix(sort, "_asc"):
		field = strings.TrimSuffix(sort, "_asc")
	}

	if col, ok := allowedInvoiceSortColumns[field]; ok {
		return col, desc
	}

	return "id", false
}
```

## Explanation

`ORDER BY` cannot take a bind parameter in standard SQL, so `Where`'s `?` placeholder mechanism has nothing to attach to for `sort` - the only safe options are to build the clause from vetted, static column names or to reject anything that doesn't match one. The fix keeps `sort` off the SQL text path entirely: `parseInvoiceSort` maps the incoming token to one of a small, fixed set of real column names (`allowedInvoiceSortColumns`) and a boolean direction, defaulting to a safe `id` ascending sort for any unrecognized value instead of passing it through. The query then uses GORM's structured `clause.OrderByColumn{Column: clause.Column{Name: column}, Desc: desc}`, which GORM renders by quoting the identifier itself rather than interpolating a string - so even the allowlisted column name is never concatenated as raw SQL. The `Where` clause was already using parameter placeholders correctly and is unchanged. This is an allowlist over a set of column names the application itself defines for its sort feature (not a security-only pattern layered onto a free-form value), so it does not reject any legitimate sort request the API is meant to support.
