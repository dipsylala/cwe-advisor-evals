## Verdict

Real SQL injection vulnerability. The `sort` parameter flows from user input directly into GORM's `Order()` method without validation, enabling arbitrary SQL injection through the ORDER BY clause.

## Source

Line 24 in `invoice_repository.go`:

```
Order(sort).
```

The `sort` parameter (line 20 function argument) originates from untrusted input and is passed unvalidated to `Order()`, which injects it directly into the SQL query string. In contrast, `accountID` and `status` parameters are correctly parameterized using placeholders in the `Where()` clause.

## Fix

Validate the `sort` parameter against a whitelist of allowed column names and sort directions before passing it to `Order()`:

```go
func (r *InvoiceRepository) Export(ctx context.Context, accountID string, status string, sort string) error {
	var invoices []Invoice
	
	// Whitelist allowed columns and directions
	allowedColumns := map[string]bool{
		"id": true, "account_id": true, "status": true, "total_cents": true,
	}
	allowedDirections := map[string]bool{
		"ASC": true, "DESC": true, "asc": true, "desc": true,
	}
	
	// Validate sort parameter; reject if not in whitelist
	if sort != "" {
		// Parse sort to extract column and direction
		parts := strings.Fields(sort)
		if len(parts) < 1 || len(parts) > 2 || !allowedColumns[parts[0]] {
			return fmt.Errorf("invalid sort column")
		}
		if len(parts) == 2 && !allowedDirections[parts[1]] {
			return fmt.Errorf("invalid sort direction")
		}
	}
	
	return r.DB.WithContext(ctx).
		Where("account_id = ? AND status = ?", accountID, status).
		Order(sort).
		Find(&invoices).Error
}
```

Alternatively, use GORM's `Clause` with `Expr()` to ensure the value is treated as a literal identifier, though validation is still preferred as a defense-in-depth measure.

## Explanation

The fix applies a strict whitelist validation before the sort parameter reaches `Order()`. By checking that the column name exists in the schema and the direction keyword is recognized, an attacker cannot inject SQL through the sort parameter. The whitelist approach is the primary defence for ORDER BY clauses because they cannot use parameterized placeholders like WHERE conditions can—the column and sort direction must be part of the query structure, not a value, so they must be validated rather than parameterized.
