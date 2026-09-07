## Verdict

The SQL injection vulnerability at line 24 is **confirmed and exploitable**. The `sort` parameter flows directly from untrusted user input (URL query parameter in `invoice_handler.go` line 9) into GORM's `Order()` method without validation. GORM's `Order()` does not escape identifiers, allowing an attacker to inject arbitrary SQL into the ORDER BY clause.

## Source

- **Attacker-controlled input**: `invoice_handler.go` line 9: `sort := r.URL.Query().Get("sort")`
- **Data flow**: `invoice_service.go` line 10 passes `sort` to `Repository.Export()`
- **Vulnerable sink**: `invoice_repository.go` line 24: `.Order(sort)` - untrusted parameter passed directly to GORM method that does not escape SQL identifiers

## Fix

The fix validates the sort parameter against an allowlist of permitted columns and directions before passing it to `Order()`. This ensures only known, safe identifiers reach the SQL sink.

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

// sortAllowlist defines the columns that may be used in ORDER BY
var sortAllowlist = map[string]bool{
	"id":          true,
	"account_id":  true,
	"status":      true,
	"total_cents": true,
}

var directionAllowlist = map[string]bool{
	"asc":  true,
	"desc": true,
}

// validateSort validates a sort parameter and returns the canonical safe form,
// or an error if the input is not in the allowlist.
func validateSort(sort string) (string, error) {
	sort = strings.TrimSpace(sort)
	if sort == "" {
		return "", nil
	}

	// Parse "[column] [direction]"
	parts := strings.Fields(sort)
	if len(parts) > 2 {
		return "", fmt.Errorf("invalid sort parameter")
	}

	column := strings.ToLower(parts[0])
	if !sortAllowlist[column] {
		return "", fmt.Errorf("invalid sort column")
	}

	direction := "asc"
	if len(parts) == 2 {
		dir := strings.ToLower(parts[1])
		if !directionAllowlist[dir] {
			return "", fmt.Errorf("invalid sort direction")
		}
		direction = dir
	}

	return fmt.Sprintf("%s %s", column, direction), nil
}

func (r *InvoiceRepository) Export(ctx context.Context, accountID string, status string, sort string) error {
	var invoices []Invoice

	// Validate and sanitize the sort parameter against allowlists
	validatedSort, err := validateSort(sort)
	if err != nil {
		return err
	}

	query := r.DB.WithContext(ctx).
		Where("account_id = ? AND status = ?", accountID, status)

	// Only apply Order if we have a validated sort clause
	if validatedSort != "" {
		query = query.Order(validatedSort)
	}

	return query.Find(&invoices).Error
}
```

## Explanation

The fix introduces an allowlist-based validation function that ensures only known column names and sort directions reach the `Order()` sink. The `validateSort()` function:

1. Trims whitespace from the user input
2. Parses the input into column and optional direction tokens
3. Validates the column name against `sortAllowlist` (the columns from the Invoice struct)
4. Validates the direction (if provided) against `directionAllowlist` (asc/desc)
5. Returns the canonical form (`"column asc"` or `"column desc"`) or an error

The `Export()` method now calls `validateSort()` before `Order()`, and passes only the validated result—never the original tainted input—to the sink. If validation fails, the method returns an error rather than attempting to execute an unsafe query. This eliminates the injection vector while preserving the original query semantics for valid inputs.

## Behaviour changes

- **Query execution**: Queries with invalid sort parameters now return an error (e.g., "invalid sort column") instead of passing the malicious input to the database.
- **Valid requests**: Requests with permitted column names and directions (e.g., `sort=id asc`, `sort=status`) continue to work unchanged; the validated canonical form is used.
- **Empty sort**: Requests with no sort parameter or an empty sort parameter continue to use the default database sort order (no ORDER BY applied).
- **Error handling**: Callers must now handle errors returned from `validateSort()` failures; this is safe because it prevents attacker-controlled data from reaching the sink.
