## Verdict

- **CWE-352** - Cross-Site Request Forgery
- **Location**: `account_routes.go:31` (route registration), sink at `account_routes.go:61` (`store.Delete(userID)`, formerly reached via the `GET /account/delete` handler)
- **Verdict**: exploitable
- **Confidence**: high

## Source

- **Source**: an inbound `GET /account/delete` request carrying the victim's session cookie. `http.CrossOriginProtection` only inspects `Sec-Fetch-Site`/`Origin` on the non-safe methods (POST/PUT/DELETE/PATCH); GET is treated as safe by definition, so a cross-site `<img>`/bare navigation reaches this route with no origin check at all, and the browser attaches the victim's session cookie automatically.
- **Call chain**: `RegisterAccountRoutes` (line 31) registers `mux.HandleFunc("GET /account/delete", deleteAccountHandler(store))` directly on the mux, bypassing `protection.Handler(...)`, which every other state-changing route in the file is wrapped in (lines 25-26).
- **Sink**: `deleteAccountHandler` reads `userID` from the session context (line 55) and calls `store.Delete(userID)` (line 61), permanently deleting the account with no CSRF check having run.

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

	// Account deletion is convenience-linked from an email notification, so
	// the GET route stays reachable for that link, but it now only renders a
	// confirmation page - it no longer mutates state itself. The confirmation
	// form POSTs to the state-changing route below, which is wrapped in
	// CrossOriginProtection like the other mutating endpoints, so a forged
	// cross-site request is rejected before the account is ever touched.
	mux.HandleFunc("GET /account/delete", deleteAccountConfirmHandler())
	mux.Handle("POST /account/delete", protection.Handler(http.HandlerFunc(deleteAccountHandler(store))))
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

// deleteAccountConfirmHandler renders the confirmation page reached from the
// account-deletion email link. It performs no state change: the page's form
// POSTs to the protected /account/delete route below, which is the route
// that actually deletes the account.
func deleteAccountConfirmHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<!DOCTYPE html>
<html>
<body>
<form method="POST" action="/account/delete">
<p>This will permanently delete your account. This action cannot be undone.</p>
<button type="submit">Confirm account deletion</button>
</form>
</body>
</html>`))
	}
}

// deleteAccountHandler permanently deletes the authenticated user's account.
// It is registered on POST and wrapped in CrossOriginProtection, so a
// cross-site request (an <img> tag, a bare navigation, or a forged form
// submission from another origin) is rejected before this handler ever runs.
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

The vulnerability was not a missing check inside the handler, it was the route's method: `http.CrossOriginProtection` validates Fetch-metadata headers only on POST/PUT/DELETE/PATCH, so registering the deletion on `GET /account/delete` put it outside the middleware's scope entirely, and a token added to that GET handler would not have helped either, since a simple cross-site navigation carries no token to check. The fix keeps the GET route - it is a link clicked from an email, so removing it would break that link - but changes what it does: it now renders a confirmation page and no longer touches the store. The actual deletion moves to a new `POST /account/delete` route wrapped in the same `protection.Handler(...)` already used for the email/password routes, so a cross-site request is rejected by Fetch-metadata checking before `deleteAccountHandler` ever runs. `deleteAccountHandler` itself, its authorization check, and its call to `store.Delete` are unchanged.

## Behaviour changes

- The email link to `GET /account/delete` no longer deletes the account on click; it now lands on a confirmation page with a "Confirm account deletion" button that POSTs to `/account/delete`. This is an intentional one-extra-click change required by the fix (a GET can never carry a same-site guarantee), not a side effect - the existing link keeps working, it just no longer performs the mutation itself.
- A new route, `POST /account/delete`, is added and is the only path that now reaches `store.Delete`. It reuses `deleteAccountHandler` unmodified, so the authorization check, error handling, and success/error status codes for the deletion itself are identical to before.
- `deleteAccountHandler`'s internal logic, arguments, return values, and status codes are unchanged - only its registration (method and CSRF wrapping) changed.
- `updateEmailHandler` and `updatePasswordHandler` are untouched.
- **Verification**: the fixed file was copied to a scratch Go module (module `csrfcheck`, `go.mod` created via `go mod init`) and checked with `go vet ./...` (Go 1.25.5) - no diagnostics, confirming the file compiles and the `http.CrossOriginProtection`/`NewCrossOriginProtection`/`Handler` API usage (already present in the original file) and the new `deleteAccountConfirmHandler` function are all well-formed.
- **Assumptions**: none beyond the language inference (Go, from file extension and `net/http` usage) and the CWE-352 mapping given, both unambiguous from the finding and file content.
