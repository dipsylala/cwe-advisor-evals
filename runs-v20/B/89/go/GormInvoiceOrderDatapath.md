## Verdict

exploitable (confidence: high)

- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
- Location: `invoice_repository.go`, line 24 - `Order(sort)` inside `InvoiceRepository.Export`

## Source

`sort := r.URL.Query().Get("sort")` in `invoice_handler.go` (line 9). The value is an
attacker-controlled HTTP query parameter with no validation applied.

Call chain:

1. `InvoiceHandler` (`invoice_handler.go:9`) reads `sort` from `r.URL.Query()`.
2. `InvoiceHandler` (`invoice_handler.go:11`) passes it unchanged to `service.ExportInvoices(r.Context(), accountID, status, sort)`.
3. `InvoiceService.ExportInvoices` (`invoice_service.go:9-11`) forwards it unchanged to `s.Repository.Export(ctx, accountID, status, sort)`.
4. `InvoiceRepository.Export` (`invoice_repository.go:24`) passes it directly into GORM's `Order(sort)`.

GORM's `Order` does not treat its argument as a bindable value - it is interpolated into the
`ORDER BY` clause of the generated SQL essentially as-is. Unlike the `Where("account_id = ? AND
status = ?", accountID, status)` call on the line above, which correctly binds `accountID` and
`status` as parameters, nothing in this chain constrains, allowlists, or parameterizes `sort`
before it reaches `Order`. An attacker can use it to inject arbitrary `ORDER BY` expressions
(e.g. subqueries or boolean conditions used for blind data exfiltration), and on some GORM
configurations to break out of the clause entirely.

**Sink contract (`Order` -> `Find` chain):**
- **Returns:** `Find(&invoices).Error` - a single `error`, non-nil on any DB or driver failure; the populated `invoices` slice itself is not returned or discarded by other means (it stays in the function's local scope, matching the pre-fix code).
- **Discards:** nothing new; the pre-fix code already ignores `invoices` after the call (it is written but never read), so a fix must not change what is exposed to the caller.
- **Arguments left implicit:** none beyond what the existing `Where` binds (`accountID`, `status`); `Order` took the entire untrusted string as its one argument with no separate identifier/direction split.
- **Failure behaviour:** any error - malformed SQL, connection failure - bubbles up through `ExportInvoices` to `InvoiceHandler`, which maps any non-nil error to `http.Error(w, "report failed", http.StatusInternalServerError)`. The caller never sees the underlying error text.

## Fix

### File: invoice_repository.go

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

// allowedSortColumns maps the sort keys accepted from callers to the
// underlying database columns. Order() cannot bind its argument as a
// query parameter, so only names listed here are permitted.
var allowedSortColumns = map[string]string{
	"id":          "id",
	"account_id":  "account_id",
	"status":      "status",
	"total_cents": "total_cents",
}

// resolveSortOrder validates a caller-supplied "column" or "column direction"
// string against the allowlisted columns and directions, and returns an
// ORDER BY clause built only from the matched, known-safe values - never
// from the original input.
func resolveSortOrder(sort string) (string, error) {
	fields := strings.Fields(sort)
	if len(fields) == 0 || len(fields) > 2 {
		return "", fmt.Errorf("invalid sort parameter: %q", sort)
	}

	column, ok := allowedSortColumns[strings.ToLower(fields[0])]
	if !ok {
		return "", fmt.Errorf("invalid sort column: %q", fields[0])
	}

	direction := "ASC"
	if len(fields) == 2 {
		switch strings.ToLower(fields[1]) {
		case "asc":
			direction = "ASC"
		case "desc":
			direction = "DESC"
		default:
			return "", fmt.Errorf("invalid sort direction: %q", fields[1])
		}
	}

	return fmt.Sprintf("%s %s", column, direction), nil
}

func (r *InvoiceRepository) Export(ctx context.Context, accountID string, status string, sort string) error {
	var invoices []Invoice
	query := r.DB.WithContext(ctx).
		Where("account_id = ? AND status = ?", accountID, status)

	if sort != "" {
		orderClause, err := resolveSortOrder(sort)
		if err != nil {
			return err
		}
		query = query.Order(orderClause)
	}

	return query.Find(&invoices).Error
}
```

## Explanation

`Order()` cannot parameterize its argument the way `Where()` does - GORM interpolates it directly
into the `ORDER BY` clause - so the fix does not try to bind `sort` as a value. Instead it treats
the identifier/direction pair as data to validate against a fixed allowlist derived from the
`Invoice` struct's actual columns (`id`, `account_id`, `status`, `total_cents`) plus the two valid
SQL sort directions (`ASC`/`DESC`). `resolveSortOrder` splits the caller's string into at most a
column token and a direction token, looks the column up in `allowedSortColumns` (case-insensitive),
validates the direction against a fixed set, and returns a clause built only from the matched
map/constant values - the original attacker-controlled string is never concatenated into the
clause or passed to `Order` itself. Any input that isn't an exact match for a known column (with
an optional known direction) is rejected with an error rather than passed through or silently
coerced, closing the injection at the one sink (`Order`) that the `Where` binding upstream doesn't
cover.

## Behaviour changes

- **New rejection path:** a `sort` value that does not match `column` or `column direction` from
  the allowlist now causes `Export` (and therefore `ExportInvoices` and the handler) to return an
  error before any query runs, which the handler already maps to `500 report failed` - the same
  external response a downstream SQL/driver error from a malformed injected value would have
  produced before the fix. Net externally-visible behaviour for malicious/malformed input is
  unchanged (still a 500); the difference is that no query is sent to the database first.
- **Empty `sort` preserved as no-op:** `sort == ""` still skips `Order(...)` entirely, exactly as
  the pre-fix code implicitly did by passing an empty string straight through, so the default
  (database-defined) row order for that case is unchanged.
- **Sort format assumption:** no specification for the accepted `sort` string format was available
  (the case fixture's `case.json` was intentionally not read). The fix assumes the format is a bare
  column name or `"<column> <direction>"` (e.g. `total_cents`, `total_cents desc`), matching the
  four `Invoice` struct fields. If the real API previously accepted a different convention (e.g. a
  leading `-` for descending, or additional non-struct columns), legitimate callers using that
  convention will now get the new rejection path instead of a sorted result until the allowlist or
  parser is adjusted to match the actual accepted format. This lowers confidence in the fix's
  drop-in compatibility, though not in its security effect.
- No changes to `invoice_handler.go` or `invoice_service.go` - both are outside the fix; they were
  copied into the compile check unmodified as call-chain context only.

## Verification

`go build ./...` and `go vet ./...` were run against the fixed `invoice_repository.go` alongside
unmodified copies of `invoice_handler.go` and `invoice_service.go`, in a scratch module outside the
repository with a minimal local stub of `gorm.io/gorm` (providing `DB`, `WithContext`, `Where`,
`Order`, `Find` with the same signatures used by the call chain), since the real GORM module
was not resolvable offline. Both commands completed with no errors or warnings. New identifiers
introduced (`fmt`, `strings` from the Go standard library; the package-level `allowedSortColumns`
map and `resolveSortOrder` function, both defined in this same file) were manually confirmed
against the standard library and the file's own declarations.
