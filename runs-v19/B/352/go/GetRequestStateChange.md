## Verdict

Exploitable. The account deletion handler is registered as a GET endpoint without CSRF protection. GET requests bypass the CrossOriginProtection middleware entirely, allowing attackers to trigger account deletion via simple cross-site requests (image tags, navigation links) that include the victim's session cookie.

## Source

Attacker-controlled HTTP request (GET method to `/account/delete` URL) from a cross-origin context, carried with the victim's session cookies.

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

	// Account deletion is performed via DELETE method and protected by CrossOriginProtection.
	// A separate GET confirmation page can be registered if needed to preserve email link compatibility.
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
// The route is registered as DELETE and protected by CrossOriginProtection middleware,
// which validates Sec-Fetch-Site headers to prevent cross-site exploitation.
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

The fix changes the account deletion route from GET to DELETE and wraps it with the CrossOriginProtection middleware. This closes the CSRF vulnerability by ensuring that deletion requests must either originate from the same site or include valid Sec-Fetch-Site and Sec-Fetch-Dest headers that are validated by the middleware. GET requests are treated as safe by CSRF protection mechanisms and bypass all origin validation; changing to DELETE forces the middleware to validate the request origin. The handler logic remains unchanged, and the Sec-Fetch-Site validation performed by CrossOriginProtection prevents exploitation via cross-site image tags, script includes, or navigation links.

## Behaviour changes

- **HTTP method change**: Route changes from GET to DELETE. Clients triggering account deletion must now send DELETE requests instead of GET requests (e.g., via XMLHttpRequest, fetch API, or HTML form with method override). Any clients relying on simple link clicks or image embeds will need to be updated to use DELETE.
- **CSRF protection enabled**: The route now validates Sec-Fetch-Site headers via CrossOriginProtection middleware. Requests missing valid Sec-Fetch-Site values will be rejected with HTTP 403 Forbidden before the handler executes.
- **Response unchanged**: The handler continues to return 204 No Content on success and 401/500 on failure; no changes to response semantics.
