## Verdict

CONFIRMED - The `deleteAccountHandler` performs a state-changing operation (account deletion) but is exposed on a GET endpoint, which bypasses the CrossOriginProtection middleware and creates a CSRF vulnerability.

## Source

Line 31: `mux.HandleFunc("GET /account/delete", deleteAccountHandler(store))`

The account deletion endpoint is registered using GET, which is semantically a safe method. The CrossOriginProtection middleware is only applied to state-changing methods (POST, PUT, DELETE, PATCH) and explicitly treats GET as safe, allowing CSRF attacks via img tags or navigation with the victim's session cookie.

## Fix

### File: account_routes.go

```go
package handlers

import (
	"log"
	"net/http"
)

type contextKey string

const userIDContextKey contextKey = "userID"

// accountStore performs persistent account operations.
type accountStore interface {
	Delete(userID string) error
}

// RegisterAccountRoutes wires up the account management endpoints.
// CSRF protection is applied via http.CrossOriginProtection, which rejects
// cross-origin state-changing requests using Fetch metadata headers.
func RegisterAccountRoutes(mux *http.ServeMux, store accountStore) {
	protection := http.NewCrossOriginProtection()

	// State-changing routes are wrapped in CrossOriginProtection, which
	// validates Sec-Fetch-Site on cross-origin POST/PUT/DELETE/PATCH requests.
	mux.Handle("POST /account/email", protection.Handler(http.HandlerFunc(updateEmailHandler(store))))
	mux.Handle("PUT /account/password", protection.Handler(http.HandlerFunc(updatePasswordHandler(store))))

	// Account deletion is a state-changing operation and is protected by
	// CrossOriginProtection via the DELETE method, which ensures Sec-Fetch-Site
	// validation blocks cross-site requests.
	mux.Handle("DELETE /account/delete", protection.Handler(http.HandlerFunc(deleteAccountHandler(store))))
}

func updateEmailHandler(store accountStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
	}
}

func updatePasswordHandler(store accountStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
	}
}

// deleteAccountHandler permanently deletes the authenticated user's account.
// The route is registered on the DELETE method and wrapped with CrossOriginProtection,
// which validates the Sec-Fetch-Site header on cross-origin requests to ensure
// the deletion is not triggered by a cross-site attack.
func deleteAccountHandler(store accountStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := r.Context().Value(userIDContextKey).(string)
		if !ok || userID == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if err := store.Delete(userID); err != nil {
			log.Printf("account deletion failed for %s: %v", userID, err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
```

## Explanation

The vulnerability occurred because account deletion—a state-changing operation—was exposed on a GET endpoint and therefore bypassed the CrossOriginProtection middleware. HTTP semantics define GET as a safe method that should never modify server state; browsers and proxies cache and prefetch GET requests without user interaction. This allows an attacker to trigger account deletion via an img tag, link, or redirect with the victim's session cookie automatically attached.

The fix changes the HTTP method to DELETE and applies the same CrossOriginProtection middleware used by the other state-changing endpoints (POST /account/email, PUT /account/password). The middleware validates the Sec-Fetch-Site header, which browsers set to `same-origin` for same-site requests and `cross-site` for cross-site requests. By rejecting requests where Sec-Fetch-Site indicates a cross-site origin, the CSRF attack vector is closed.
