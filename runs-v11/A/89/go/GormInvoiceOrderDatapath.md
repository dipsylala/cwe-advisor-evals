## Verdict

**CWE-89 SQL Injection - CONFIRMED**

The `Order()` method accepts an unsanitized `sort` parameter at line 24, allowing SQL injection.

## Source

File: `evals/cases/89/go/GormInvoiceOrderDatapath/invoice_repository.go`, line 24

The `Export()` method receives a `sort` string parameter and passes it directly to GORM's `Order()` method without validation:

```
Order(sort).
```

Unlike the parameterized `Where()` clause above it, `Order()` does not support query parameters and constructs raw SQL from its string argument. An attacker can inject SQL by providing a malicious `sort` value.

## Fix

Validate the `sort` parameter against a whitelist of allowed column names and sort directions:

```go
func (r *InvoiceRepository) Export(ctx context.Context, accountID string, status string, sort string) error {
	// Whitelist allowed sort columns and directions
	allowedColumns := map[string]bool{
		"id":          true,
		"id ASC":      true,
		"id DESC":     true,
		"account_id":  true,
		"account_id ASC":  true,
		"account_id DESC": true,
		"status":      true,
		"status ASC":  true,
		"status DESC": true,
		"total_cents": true,
		"total_cents ASC":  true,
		"total_cents DESC": true,
	}

	if !allowedColumns[sort] {
		return fmt.Errorf("invalid sort parameter")
	}

	var invoices []Invoice
	return r.DB.WithContext(ctx).
		Where("account_id = ? AND status = ?", accountID, status).
		Order(sort).
		Find(&invoices).Error
}
```

Add `"fmt"` to the imports.

## Explanation

The `Order()` method in GORM does not support parameterized queries. Unlike the `Where()` method which accepts `?` placeholders and separate arguments, `Order()` constructs SQL directly from its string argument. This makes it vulnerable to SQL injection if the input is not validated.

The fix uses a whitelist of allowed sort expressions (column names with optional ASC/DESC modifiers) and rejects any input that doesn't match. This ensures only safe SQL is generated while preserving the intended functionality of allowing callers to specify sort order.

Parameterization alone cannot fix this—the sort order is structural SQL syntax, not a data value. A whitelist is the appropriate defense.
