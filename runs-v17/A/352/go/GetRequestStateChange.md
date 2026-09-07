## Verdict

Confirmed. The `deleteAccountHandler` is registered on GET, which bypasses `http.CrossOriginProtection` because the middleware only validates state-changing methods (POST, PUT, DELETE, PATCH). A cross-origin request to `GET /account/delete` carries the victim's session cookie without Sec-Fetch-Site or origin validation, allowing account deletion via CSRF.

## Source

Line 31: `mux.HandleFunc("GET /account/delete", deleteAccountHandler(store))`

The handler performs a state-changing operation (permanent account deletion) on a method the CSRF protection considers safe by default.

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

	// Account deletion is a state-changing operation and must use a non-safe HTTP
	// method (DELETE) and be protected against CSRF via CrossOriginProtection.
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
// The route uses DELETE (a non-safe method) and is wrapped in CrossOriginProtection
// to validate Sec-Fetch-Site on cross-origin requests, preventing CSRF attacks.
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

GET is semantically a safe method and HTTP CSRF protections (including Go's `CrossOriginProtection`) skip validation for safe methods by design. Attackers exploit this by embedding CSRF payloads—`<img src="...">` tags, `<link>`, or navigation—that trigger GET requests carrying the victim's session cookie.

The fix changes the route from `GET /account/delete` to `DELETE /account/delete` and wraps it with `protection.Handler()`, bringing it into the same CSRF-protected family as the other state-changing endpoints. The DELETE method signals the operation's state-changing nature and ensures Sec-Fetch-Site validation occurs on cross-origin requests. Clients must now explicitly construct and send a DELETE request (typically via `fetch()`, `XMLHttpRequest`, or a form with method-override), which triggers the browser's Fetch metadata header that the protection validates.

E:/Github/cwe-advisor/evals/runs-v17/A/352/go/GetRequestStateChange.md
