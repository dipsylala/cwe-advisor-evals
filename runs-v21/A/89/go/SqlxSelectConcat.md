## Verdict
Confirmed SQL injection via unsafe string concatenation in query construction.

## Source
`category := r.URL.Query().Get("category")` at line 27 — untrusted HTTP request parameter.

## Fix
### File: SqlxSelectConcat.go

```go
package main

import (
	"encoding/json"
	"fmt"
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

	query := "SELECT id, name, category, price FROM products WHERE category = ?"

	var products []Product
	// SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
	err := h.DB.Select(&products, query, category)
	if err != nil {
		http.Error(w, "failed to load products", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(products)
}
```

## Explanation
The original code builds the SQL query by string concatenation with `fmt.Sprintf()`, which allows the `category` parameter to inject arbitrary SQL syntax. The fix uses sqlx's built-in parameterized query support: the query string contains a `?` placeholder, and the `category` value is passed as a separate argument to `Select()`. The database driver binds the value safely to the parameter, preventing SQL injection. This approach treats user input as data, not executable code, and is the standard defensive pattern for all SQL operations in Go with sqlx.
