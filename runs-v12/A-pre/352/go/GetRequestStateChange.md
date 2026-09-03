## Verdict

CONFIRMED: CWE-352 (Cross-Site Request Forgery)

## Source

Line 31 in `account_routes.go`:
```go
mux.HandleFunc("GET /account/delete", deleteAccountHandler(store))
```

The account deletion endpoint is registered as a GET request without CSRF protection. Stateful operations must use POST (or PUT/DELETE/PATCH) and be protected by the CrossOriginProtection middleware that validates Sec-Fetch-Site headers on state-changing methods.

## Fix

```go
func RegisterAccountRoutes(mux *http.ServeMux, store accountStore) {
	protection := http.NewCrossOriginProtection()

	// State-changing routes are wrapped in CrossOriginProtection, which
	// validates Sec-Fetch-Site on cross-origin POST/PUT/DELETE/PATCH requests.
	mux.Handle("POST /account/email", protection.Handler(http.HandlerFunc(updateEmailHandler(store))))
	mux.Handle("PUT /account/password", protection.Handler(http.HandlerFunc(updatePasswordHandler(store))))
	mux.Handle("POST /account/delete", protection.Handler(http.HandlerFunc(deleteAccountHandler(store))))
}
```

Change from `mux.HandleFunc("GET /account/delete", ...)` to `mux.Handle("POST /account/delete", protection.Handler(...))`, wrapping the handler with CrossOriginProtection like the other state-changing endpoints.

## Explanation

Account deletion is a state-changing operation that modifies server state (deletes a user account). Exposing it as a GET request creates a CSRF vulnerability because:

1. GET requests are treated as safe and bypass the CrossOriginProtection middleware
2. A cross-origin request (attacker's web page) can trigger deletion via `<img>` tags, `<script>`, or navigation
3. The victim's session cookie is automatically sent with the request, authenticating it

The fix changes the method to POST and wraps the handler with `protection.Handler()`, which validates the `Sec-Fetch-Site` header on all state-changing requests. This prevents cross-origin requests initiated by attackers from succeeding, while still allowing legitimate requests from the same origin.
