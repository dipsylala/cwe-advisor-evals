## Verdict

Exploitable. A GET request to `/account/delete` performs account deletion using the authenticated user's session cookie without CSRF validation. `CrossOriginProtection` validates only non-safe HTTP methods (POST/PUT/DELETE/PATCH), so GET requests pass through entirely. An attacker can trigger this action cross-site via `<img>`, `<a>`, or fetch, exploiting any user with an active session.

## Source

HTTP GET request from cross-site context (attacker-controlled web page, email, etc.) sent to `https://victim.com/account/delete`, carrying the victim's session cookie.

## Fix

**Vulnerable code (lines 31, 53-69):**
```go
mux.HandleFunc("GET /account/delete", deleteAccountHandler(store))

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

**Fixed code:**
```go
import (
	"fmt"
	"log"
	"net/http"
)

// In RegisterAccountRoutes, replace line 31 with:
mux.Handle("GET /account/delete", http.HandlerFunc(getDeleteConfirmationHandler()))
mux.Handle("POST /account/delete", protection.Handler(http.HandlerFunc(deleteAccountHandler(store))))

// Replace the deleteAccountHandler function:
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

// Add a new handler for the GET confirmation page:
func getDeleteConfirmationHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head><title>Delete Account</title></head>
<body>
<h1>Delete Account</h1>
<p>Are you sure you want to permanently delete your account? This action cannot be undone.</p>
<form method="POST" action="/account/delete">
<button type="submit">Delete My Account</button>
<button type="button" onclick="window.history.back()">Cancel</button>
</form>
</body>
</html>`)
	}
}
```

## Explanation

The fix separates the confirmation UI (safe GET) from the state-changing operation (protected POST). The email notification link now points to `GET /account/delete`, which displays a confirmation page to the user. The confirmation page contains an HTML form that POSTs to the same `/account/delete` endpoint, which is now wrapped with `CrossOriginProtection`. When a user clicks "Delete My Account", the browser sends a POST request that includes the Sec-Fetch-Site header. `CrossOriginProtection` validates this header; if the request originates from a different site, it is rejected with 403. A legitimate same-origin form POST passes the check. The `deleteAccountHandler` logic remains unchanged and now only executes for POST requests. Attackers can no longer trigger deletion via cross-site GET/image/navigation, even with the victim's session cookie present.

## Behaviour changes

- GET `/account/delete` now returns a 200 OK HTML confirmation page instead of deleting the account. Users who click the email link see a confirmation prompt instead of immediate deletion.
- POST `/account/delete` is now the state-changing operation and is protected by `CrossOriginProtection`, validating `Sec-Fetch-Site` headers.
- The response for a legitimate POST deletion remains 204 No Content, unchanged from the original.
- Added import: `"fmt"` for HTML rendering (standard library, no external dependency).
- Added new function `getDeleteConfirmationHandler()` that returns a safe GET handler. The original `deleteAccountHandler` is now called only via POST and no longer processes GET requests.
