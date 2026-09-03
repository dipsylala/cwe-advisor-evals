## Verdict

Confirmed. A state-changing operation (account deletion) is reachable via GET request without CSRF protection. The route bypasses `http.CrossOriginProtection` because the middleware validates only non-safe methods (POST, PUT, DELETE, PATCH), leaving GET requests unprotected even when the handler mutates state. A cross-origin request (e.g., an `<img>` tag, a direct link from another site) triggers deletion with the victim's session cookie attached and no origin or authenticity check.

## Source

HTTP GET request to `/account/delete` at line 31 in `RegisterAccountRoutes()`, calling `deleteAccountHandler()` which performs state-changing operations without authentication of request origin.

## Fix

Move the deletion operation from GET to POST, wrap the POST route in `http.CrossOriginProtection`, and preserve the GET route as a confirmation page that renders an HTML form. This maintains backward compatibility with email links (which land on the confirmation page) while ensuring the actual deletion operation is protected.

**Route registration (updated):**

```go
// Account deletion confirmation is exposed as GET so email links can be clicked directly.
// The actual state-changing operation is POST and is wrapped in CrossOriginProtection.
mux.HandleFunc("GET /account/delete", deleteAccountConfirmationHandler())
mux.Handle("POST /account/delete", protection.Handler(http.HandlerFunc(deleteAccountHandler(store))))
```

**New confirmation handler:**

```go
// deleteAccountConfirmationHandler renders a confirmation page for account deletion.
// The form on the confirmation page POSTs to the protected DELETE endpoint with CSRF token.
func deleteAccountConfirmationHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		// Render confirmation page with POST form
		w.Write([]byte(`
<!DOCTYPE html>
<html>
<head>
	<title>Delete Account</title>
</head>
<body>
	<h1>Delete Account</h1>
	<p>This action cannot be undone. Are you sure?</p>
	<form method="POST" action="/account/delete">
		<button type="submit">Delete My Account</button>
		<button type="button" onclick="history.back()">Cancel</button>
	</form>
</body>
</html>
		`))
	}
}
```

**Updated deletion handler (method signature unchanged, but now registered on POST):**

```go
// deleteAccountHandler permanently deletes the authenticated user's account.
// This handler is registered on POST and wrapped in CrossOriginProtection,
// which validates Sec-Fetch-Site on cross-origin requests.
// The GET route (deleteAccountConfirmationHandler) provides a confirmation page
// so email links continue to work - they render the form, which then POSTs with CSRF protection.
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

The vulnerability exists because `http.CrossOriginProtection` only inspects non-safe HTTP methods (POST, PUT, DELETE, PATCH) and treats GET as safe by definition, skipping the middleware entirely. This allows a cross-site request to trigger account deletion: an attacker can craft an `<img>` tag, a direct link, or a page redirect pointing to `/account/delete`, and the browser will attach the victim's session cookie to the request, causing deletion with no origin validation or CSRF token check.

The fix moves the deletion operation to POST where `http.CrossOriginProtection` validates the `Sec-Fetch-Site` header, rejecting cross-origin requests and confirming same-origin origin. The GET route is preserved as a confirmation page—this maintains backward compatibility with existing email links that point to `/account/delete`. When followed, the email link now renders an HTML form that the user must submit to complete the deletion, which POSTs to the protected endpoint. This two-step flow ensures email-based links remain functional while closing the CSRF vector.

## Behaviour changes

- **GET `/account/delete`** now renders a confirmation page (HTTP 200) instead of deleting the account. Users see a confirmation form with delete and cancel buttons.
- **Existing email links to `/account/delete`** continue to work without modification. They now load the confirmation page instead of completing the deletion directly, adding a user-confirmation step.
- **Actual account deletion** now requires a POST request to `/account/delete` with a valid CSRF token (verified by `http.CrossOriginProtection`). Same-origin requests (from the confirmation form) include the token automatically; cross-origin requests are rejected with HTTP 403.
- **No change to the deletion handler's implementation** — it still extracts userID from context, validates authentication, calls `store.Delete()`, and returns the same status codes. The handler's logic is preserved; only its registration method (POST instead of GET) and protection wrapper change.
