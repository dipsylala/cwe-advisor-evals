package gorminvoice

import "net/http"

func InvoiceHandler(service *InvoiceService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accountID := r.Header.Get("X-Account-Id")
		status := r.URL.Query().Get("status")
		sort := r.URL.Query().Get("sort")

		if err := service.ExportInvoices(r.Context(), accountID, status, sort); err != nil {
			http.Error(w, "report failed", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
