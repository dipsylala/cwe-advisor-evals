## Verdict
exploitable

## Source
Cross-origin attacker-controlled request: GET request to `/account/delete` from a malicious website using an `<img>` tag, navigation link, or fetch call.

## Fix
Relocate the state-changing operation (account deletion) from GET to POST, and wrap the POST handler with `http.CrossOriginProtection`. The GET handler is retained as a safe confirmation page that renders an HTML form POSting to the protected endpoint. Email links continue to work by directing users to the GET confirmation page.

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
	// The GET route serves a confirmation page; the POST route performs the deletion
	// and is protected by CrossOriginProtection.
	mux.HandleFunc("GET /account/delete", deleteConfirmationHandler())
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

// deleteConfirmationHandler renders a confirmation page for account deletion.
// This is a safe, idempotent operation that shows the user a confirmation
// form before proceeding with the actual deletion.
func deleteConfirmationHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>Confirm Account Deletion</title></head>
<body>
<h1>Confirm Account Deletion</h1>
<p>Are you sure you want to delete your account? This action cannot be undone.</p>
<form method="POST" action="/account/delete">
<button type="submit">Delete My Account</button>
<a href="/">Cancel</a>
</form>
</body>
</html>`))
	}
}

// deleteAccountHandler permanently deletes the authenticated user's account.
// The POST request passes through CrossOriginProtection, which validates
// Fetch metadata headers to prevent cross-site request forgery.
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
The original code registered the account deletion handler as a GET endpoint, which is bypassed by `http.CrossOriginProtection` middleware. The middleware only validates non-safe HTTP methods (POST, PUT, DELETE, PATCH), treating GET as safe by design. This allowed cross-site attackers to trigger account deletion via an `<img>` tag or navigation link without any CSRF protection. The fix moves the state-changing operation to POST and wraps it with `CrossOriginProtection`, which validates Fetch metadata headers on cross-origin requests. The GET endpoint is retained as a safe confirmation page that renders an HTML form; email links continue to work by directing users to this page where they explicitly confirm the deletion through a form submission.

## Behaviour changes
1. **GET /account/delete now returns an HTML confirmation page** instead of directly deleting the account. This is a behaviour change but intentional and necessary: users can no longer delete their account by clicking a bare link; they must explicitly confirm via a button on a form.
2. **POST /account/delete now performs the deletion** (previously performed by GET). This is the state-changing operation and is now protected by CrossOriginProtection.
3. **Email links must now route through a confirmation step**. Links from email notifications will now land on a confirmation page that requires explicit user action (button click) before proceeding with deletion. This matches the root guidance requirement to "keep a GET at that URL that renders a confirmation page whose form POSTs to the state-changing route."
4. **No changes to handler signatures, return values, or error handling contracts** — the sink's behavior with respect to success, authorization, and error responses is identical.
