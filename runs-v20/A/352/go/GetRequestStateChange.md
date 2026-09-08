## Verdict

Confirmed. `account_routes.go` registers account deletion on `GET /account/delete` (line 31), calling `deleteAccountHandler`, which performs the deletion directly from that handler. `http.CrossOriginProtection` (constructed at line 21 and applied to the email/password routes) only validates non-safe methods (POST, PUT, DELETE, PATCH); GET is treated as safe by definition and is never passed through `protection.Handler`. A cross-site `<img src="https://victim-site/account/delete">` or a bare navigation therefore triggers the deletion using the victim's ambient session cookie, with no `Sec-Fetch-Site` or origin check performed at all. This is a classic state-changing GET CSRF gap.

## Source

The forged request is the untrusted input: any cross-origin page that gets a victim's browser to issue a GET to `/account/delete` (an `<img>` tag, a `<link>` prefetch, an auto-submitting anchor, or simple navigation) while the victim holds an authenticated session cookie for the target site. The browser attaches the session cookie automatically, and the handler trusts that ambient credential without any per-request proof that the request was intentionally initiated by the user on this origin.

## Fix

### File: account_routes.go
```go
package handlers

import (
	"fmt"
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
	// clicking the link must still work as a plain GET. The GET handler no
	// longer performs the deletion itself: it only renders a same-site
	// confirmation page whose form submits a POST to /account/delete. That
	// POST is a state-changing request, so it is wrapped in
	// CrossOriginProtection like the other mutating routes above, and a
	// cross-site page cannot forge the POST without failing the Sec-Fetch-Site
	// check (and has no way to read the confirmation page's response to
	// script an automated submission of it, since it is a distinct origin).
	mux.HandleFunc("GET /account/delete", confirmDeleteAccountHandler())
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

// confirmDeleteAccountHandler renders a same-site confirmation page reachable
// by a plain GET (so the email link still works). It performs no state
// change: it only serves a form that POSTs to /account/delete, which is the
// route that actually deletes the account and is protected accordingly.
func confirmDeleteAccountHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!DOCTYPE html>
<html>
<body>
<form method="POST" action="/account/delete">
<p>This will permanently delete your account.</p>
<button type="submit">Confirm account deletion</button>
</form>
</body>
</html>`)
	}
}

// deleteAccountHandler permanently deletes the authenticated user's account.
// It is only reachable via the CrossOriginProtection-wrapped POST route
// registered above, so a cross-origin request cannot reach it without
// passing the Sec-Fetch-Site/origin validation performed by protection.Handler.
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

The root cause was not the choice of `http.CrossOriginProtection` (that mechanism does correctly guard the other two mutating routes) but the decision to perform the actual deletion from a GET handler, which the middleware treats as safe by design and never inspects. The fix keeps the email link working exactly as before - a plain GET still loads successfully with no auth or method change required of the link itself - but moves the side effect behind a same-site form POST to `/account/delete`. That POST is now wrapped in `protection.Handler`, so `CrossOriginProtection` validates `Sec-Fetch-Site`/origin on it the same way it already does for `/account/email` and `/account/password`. A cross-site page can still cause the victim's browser to load the confirmation GET, but it cannot forge the confirming POST: browsers send `Sec-Fetch-Site: cross-site` on a cross-origin auto-submit, which `CrossOriginProtection` rejects, and the cross-site page has no way to read the confirmation page's HTML (blocked by same-origin policy) to script a submission that would appear same-site. `deleteAccountHandler` itself is unchanged - the existing authentication check via `userIDContextKey` and the store error handling are preserved - only the routing and the addition of an intermediate confirmation step change.
