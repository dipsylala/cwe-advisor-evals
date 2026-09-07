## Verdict

The CWE-352 finding is valid. The GET /account/delete endpoint performs a state-changing operation (account deletion) without CSRF protection, making it vulnerable to cross-site request forgery attacks via the victim's authenticated session.

## Source

- **Sink**: Line 31, `mux.HandleFunc("GET /account/delete", deleteAccountHandler(store))`
- **Handler**: `deleteAccountHandler` (lines 53–69) calls `store.Delete(userID)` to permanently delete the user's account
- **Vulnerability path**: An authenticated user receives a malicious link or image tag from an attacker's site. The browser sends a GET request to the endpoint with the victim's session cookie attached. Since GET is treated as a safe method by `http.CrossOriginProtection`, the middleware skips validation entirely. The handler executes `store.Delete()` without any CSRF token or Fetch metadata check.

## Fix

Move the state-changing operation from GET to POST and apply `http.CrossOriginProtection`. Keep GET as a confirmation page (per CWE-352 guidance: "keep a GET at that URL that renders a confirmation page whose form POSTs").

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

	// Account deletion is convenience-linked from an email notification.
	// The GET endpoint shows a confirmation page; the POST endpoint performs the deletion.
	// The POST endpoint is wrapped in CrossOriginProtection to prevent CSRF attacks.
	mux.HandleFunc("GET /account/delete", deleteAccountConfirmationHandler())
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

// deleteAccountConfirmationHandler renders a confirmation page for account deletion.
// The form on the page POSTs to the same URL, which is protected by CrossOriginProtection.
func deleteAccountConfirmationHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>Delete Account</title></head>
<body>
<h1>Delete Account</h1>
<p>This action cannot be undone.</p>
<form method="POST" action="/account/delete">
  <button type="submit">Confirm Deletion</button>
  <a href="/">Cancel</a>
</form>
</body>
</html>`))
	}
}

// deleteAccountHandler permanently deletes the authenticated user's account.
// This endpoint accepts POST requests only and is protected by CrossOriginProtection,
// which validates Sec-Fetch-Site headers to prevent cross-site forgery attacks.
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

The fix addresses the CSRF vulnerability by converting the state-changing operation from GET (unprotected, triggered by navigation/image tags) to POST (protected by `http.CrossOriginProtection`).

When the fix is deployed:

1. **GET /account/delete** no longer executes deletion; it renders an HTML confirmation page with a POST form
2. **POST /account/delete** performs the deletion and is wrapped with `http.CrossOriginProtection`, which validates the `Sec-Fetch-Site` header automatically sent by the browser
3. Legitimate form submissions from the same site include `Sec-Fetch-Site: same-origin`, passing validation
4. Cross-site POST attempts receive `Sec-Fetch-Site: cross-site`, which the middleware rejects before the handler runs

Email links to GET /account/delete continue to work (maintaining the convenience-link design), but now require the user to see and confirm the action on the confirmation page. Attackers cannot trigger deletion without a browser-protected form submission from the same site.

## Behaviour changes

- **GET /account/delete**: Previously executed `store.Delete()` directly; now displays an HTML confirmation page with a button that POSTs the deletion request
- **POST /account/delete**: New endpoint; receives the deletion confirmation and is protected by `http.CrossOriginProtection`
- Email links pointing to /account/delete no longer trigger immediate account deletion; users must land on the confirmation page and explicitly submit the form
- Cross-site POST requests to /account/delete are rejected with implicit 403 by `http.CrossOriginProtection` before the handler body runs
