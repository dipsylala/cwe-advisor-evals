## Verdict

Exploitable. The `GET /account/delete` endpoint performs account deletion without any CSRF protection. Since CrossOriginProtection middleware validates only non-safe HTTP methods (POST, PUT, DELETE, PATCH) and treats GET as safe by definition, a cross-origin attacker can embed a link or image tag triggering deletion with the victim's session cookie attached, with no origin validation ever performed.

## Source

**File**: evals/cases/352/go/GetRequestStateChange/account_routes.go  
**Line**: 31 (sink) and 53-68 (handler)

```go
mux.HandleFunc("GET /account/delete", deleteAccountHandler(store))
```

The registration exposes the deleteAccountHandler on GET, bypassing the CrossOriginProtection middleware that guards the POST and PUT routes. The handler performs an authenticated state change (account deletion) in response to an unauthenticated request origin.

## Fix

**Vulnerable code** (lines 20-31, handler 53-68):

```go
func RegisterAccountRoutes(mux *http.ServeMux, store accountStore) {
	protection := http.NewCrossOriginProtection()

	mux.Handle("POST /account/email", protection.Handler(http.HandlerFunc(updateEmailHandler(store))))
	mux.Handle("PUT /account/password", protection.Handler(http.HandlerFunc(updatePasswordHandler(store))))

	// Vulnerable: state change exposed on GET, no CSRF protection
	mux.HandleFunc("GET /account/delete", deleteAccountHandler(store))
}

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

**Fixed code**:

```go
func RegisterAccountRoutes(mux *http.ServeMux, store accountStore) {
	protection := http.NewCrossOriginProtection()

	mux.Handle("POST /account/email", protection.Handler(http.HandlerFunc(updateEmailHandler(store))))
	mux.Handle("PUT /account/password", protection.Handler(http.HandlerFunc(updatePasswordHandler(store))))

	// GET renders a confirmation page; actual deletion requires POST with CSRF protection
	mux.HandleFunc("GET /account/delete", confirmDeleteAccountHandler(store))
	mux.Handle("POST /account/delete", protection.Handler(http.HandlerFunc(deleteAccountHandler(store))))
}

func confirmDeleteAccountHandler(store accountStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Render a confirmation page with a form that POSTs to the protected route
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
<!DOCTYPE html>
<html>
<head><title>Confirm Account Deletion</title></head>
<body>
<h1>Delete Account</h1>
<p>This action cannot be undone. Click the button below to permanently delete your account and all associated data.</p>
<form method="POST" action="/account/delete">
	<button type="submit">Permanently Delete My Account</button>
</form>
<p><a href="/account">Cancel</a></p>
</body>
</html>
		`))
	}
}

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

The fix separates concerns between navigation and state change. The original code violates the CWE-352 remediation principle that state-changing operations must never be exposed on safe HTTP methods. By registering the deletion logic on POST instead of GET, the handler now passes through the CrossOriginProtection middleware, which validates the Sec-Fetch-Site header and rejects cross-origin requests.

The GET endpoint is preserved as a confirmation page so that email links and bookmarks still work—they display a form prompting the user to confirm deletion. The form POSTs to the protected route, preventing automatic execution via image tags, link navigation, or other cross-site mechanisms. CrossOriginProtection rejects the POST if it originates from a different domain, requiring the Fetch metadata headers that only browsers send for same-origin POST requests.

## Behaviour changes

1. **GET /account/delete now returns HTML confirmation page instead of deleting immediately** — Users who follow an email link or bookmark to `/account/delete` now see a confirmation page with a form rather than having their account deleted automatically. This is the intended behavior when a link exists for convenience; it provides a human-in-the-loop gate preventing accidental deletion. Links placed by the application (email notifications) remain functional; users click the link, see the form, and click the button to confirm.

2. **Actual deletion requires POST with Sec-Fetch-Site header** — The POST to `/account/delete` is subject to CrossOriginProtection validation, which requires `Sec-Fetch-Site: same-origin` (sent by browsers for same-origin requests) and rejects requests with `Sec-Fetch-Site: cross-site` or missing. Non-browser clients that do not support Fetch metadata headers cannot trigger deletion from cross-origin contexts, closing the CSRF vector.

3. **No change to session authentication or authorization** — The user must still be authenticated (have a valid userID in the request context) to delete; the fix does not alter the authentication check at line 55-58. The fix addresses only the origin validation aspect of CSRF, not authentication.
