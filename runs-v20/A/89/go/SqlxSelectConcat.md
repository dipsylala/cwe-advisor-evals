## Verdict

Confirmed. The `category` query parameter is concatenated directly into the SQL string via `fmt.Sprintf` and executed with `h.DB.Select`, allowing SQL injection.

## Source

`r.URL.Query().Get("category")` in `ListByCategory` (`SqlxSelectConcat.go:27`) - an attacker-controlled HTTP query parameter.

## Fix

### File: SqlxSelectConcat.go

```go
package main

import (
	"encoding/json"
	"net/http"

	"github.com/jmoiron/sqlx"
)

// Product is a row from the products table.
type Product struct {
	ID       int     `db:"id"`
	Name     string  `db:"name"`
	Category string  `db:"category"`
	Price    float64 `db:"price"`
}

// ProductHandler serves product listings filtered by category.
type ProductHandler struct {
	DB *sqlx.DB
}

// ListByCategory returns all products in the category given by the
// "category" query parameter.
func (h *ProductHandler) ListByCategory(w http.ResponseWriter, r *http.Request) {
	category := r.URL.Query().Get("category")

	const query = "SELECT id, name, category, price FROM products WHERE category = ?"

	var products []Product
	err := h.DB.Select(&products, h.DB.Rebind(query), category)
	if err != nil {
		http.Error(w, "failed to load products", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(products)
}
```

## Explanation

The original code built the SQL statement with `fmt.Sprintf("... WHERE category = '%s'", category)`, splicing the raw, attacker-controlled `category` value into the query text. Any value containing a single quote (or other SQL metacharacters) breaks out of the intended string literal and lets the caller alter the query's logic (e.g. `' OR '1'='1`) or chain additional clauses, which is classic SQL injection.

The fix keeps the query as a parameterized statement: the `category` value is replaced with a placeholder (`?`) and passed as a separate bind argument to `h.DB.Select`, rather than being interpolated into the SQL text. `sqlx.DB.Rebind` converts the `?` placeholder to the bind-variable syntax the underlying driver expects (e.g. `$1` for PostgreSQL, `?` for MySQL/SQLite), so the fix works regardless of which `database/sql` driver `h.DB` wraps. With this approach the database driver sends the query and the parameter separately, so the value is always treated as data, never as part of the SQL grammar, and no allowlist or escaping of `category` is needed. The `fmt` import is no longer used and was removed since it was only needed for the injected `Sprintf` call.
