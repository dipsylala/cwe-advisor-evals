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

	query := fmt.Sprintf("SELECT id, name, category, price FROM products WHERE category = '%s'", category)

	var products []Product
	// SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
	err := h.DB.Select(&products, query)
	if err != nil {
		http.Error(w, "failed to load products", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(products)
}
