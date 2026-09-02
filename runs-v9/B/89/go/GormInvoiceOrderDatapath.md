## Verdict

- **CWE-89** - Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
- **Location**: `invoice_repository.go`, `InvoiceRepository.Export`, line 24 (`.Order(sort)`)
- **Verdict**: exploitable
- **Confidence**: high
- **Assumptions**: none - the call chain is fully present across the three files and the taint path is unambiguous.

## Source

- **Source**: `sort := r.URL.Query().Get("sort")` in `InvoiceHandler` (`invoice_handler.go`, line 9) - an attacker-controlled HTTP query parameter with no validation at the boundary.
- **Path**: `InvoiceHandler` passes `sort` unchanged into `service.ExportInvoices(r.Context(), accountID, status, sort)` (`invoice_handler.go`, line 11) -> `InvoiceService.ExportInvoices` passes it straight through to `s.Repository.Export(ctx, accountID, status, sort)` (`invoice_service.go`, line 10) -> `InvoiceRepository.Export` interpolates it into `.Order(sort)` (`invoice_repository.go`, line 24).
- **Sink**: GORM's `Order()` builder. Per the Go/GORM guidance, `Order` does not escape its input; unlike `Where("account_id = ? AND status = ?", accountID, status)` on line 23, which binds `accountID` and `status` as parameters, `sort` is passed to `Order` as a raw clause. An attacker can supply a value such as `id; DROP TABLE invoices;--` (dialect-dependent) or, more reliably, use `Order` to inject arbitrary SQL fragments (e.g. subqueries, `CASE` expressions for boolean/error-based extraction) since GORM emits the string largely as-is into `ORDER BY`.
- **Sink contract** (`InvoiceRepository.Export`):
  - **Returns**: an `error` - `nil` on success, the underlying `*gorm.DB.Error` otherwise. `invoices` itself is populated but not returned to the caller (see Discards).
  - **Discards**: the populated `invoices` slice is never returned or used - `Export`'s only observable output is the error. The handler further collapses that error to a generic 500 with no detail.
  - **Arguments left implicit**: no `Limit`/context deadline beyond the inherited `ctx`; behaviour here is unchanged by the fix.
  - **Failure behaviour**: any GORM error (including a malformed generated query) propagates up through `ExportInvoices` to the handler, which returns `http.StatusInternalServerError` and does not leak the underlying error text to the client.

## Fix

No third-party library change is needed - the fix is entirely in how `invoice_repository.go` uses the existing `gorm.io/gorm` API.

Vulnerable code (`invoice_repository.go`):

```go
func (r *InvoiceRepository) Export(ctx context.Context, accountID string, status string, sort string) error {
	var invoices []Invoice
	return r.DB.WithContext(ctx).
		Where("account_id = ? AND status = ?", accountID, status).
		Order(sort). // sort is attacker-controlled and passed unvalidated into ORDER BY
		Find(&invoices).Error
}
```

Fixed code:

```go
// allowedInvoiceSorts maps caller-supplied sort keys to the literal ORDER BY
// clause that reaches GORM. Only keys present here may ever reach Order();
// any other value is rejected before a query is built.
var allowedInvoiceSorts = map[string]string{
	"total_cents":      "total_cents ASC",
	"total_cents_desc": "total_cents DESC",
	"status":           "status ASC",
	"status_desc":      "status DESC",
	"id":               "id ASC",
	"id_desc":          "id DESC",
}

func (r *InvoiceRepository) Export(ctx context.Context, accountID string, status string, sort string) error {
	query := r.DB.WithContext(ctx).
		Where("account_id = ? AND status = ?", accountID, status)

	if sort != "" {
		orderClause, ok := allowedInvoiceSorts[sort]
		if !ok {
			return fmt.Errorf("invalid sort value: %q", sort)
		}
		query = query.Order(orderClause)
	}

	var invoices []Invoice
	return query.Find(&invoices).Error
}
```

(`invoice_repository.go`'s import block gains `"fmt"` alongside the existing `"context"` and `"gorm.io/gorm"`.)

## Explanation

`sort` is a sort *identifier*, not a data value, so it cannot be bound as a `Where`-style placeholder the way `accountID` and `status` already are - GORM's `Order` builder emits its argument close to verbatim into the `ORDER BY` clause. The fix breaks the taint by validating `sort` against a fixed `allowedInvoiceSorts` map and using only the map's resolved, hard-coded clause with `Order`; the caller-supplied string itself never reaches the query after the lookup succeeds. An unrecognized `sort` value is rejected with an error rather than silently substituted or passed through, so no attacker-influenced string can ever reach `Order`. `accountID` and `status` were already safe (bound via `Where("... = ? AND ... = ?", ...)`) and are unchanged.

## Behaviour changes

- **Invalid/unrecognized `sort` values now cause `Export` to return an error instead of running a query.** Previously any string reached `Order()` unvalidated (this was the vulnerability); now a `sort` value outside the allowlist is rejected before the database is queried. Via the existing handler, this surfaces as `http.StatusInternalServerError` instead of a (potentially exploited or malformed) query result - the same failure path the handler already uses for any other repository error, so no new error-handling branch is introduced.
- **Only the six allowlisted sort orders are reachable**; a legitimate caller who was relying on some other free-form GORM order syntax (e.g. `"total_cents, status desc"`) will need that combination added to `allowedInvoiceSorts` explicitly. This is a deliberate narrowing required to close the injection - identifiers/order direction cannot be parameterized, so a fixed, reviewed set of permitted clauses is the only way to accept a caller-chosen sort safely.
- **Empty `sort` (`""`) is preserved as a no-op**, matching the original code's behaviour of calling `Order("")` for an absent query parameter - `Order` is now skipped entirely in that case rather than invoked with an empty string, leaving the result set in GORM/the database's default order, same as before.
- No change to `accountID`/`status` handling, the `Where` clause, the returned error type, or the discarded `invoices` output.
