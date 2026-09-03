## Verdict
**VULNERABLE**: The `/settings/email` endpoint, which performs a state-changing operation (user email modification), is registered on `apiMux` without CSRF protection while other sensitive operations are protected via `protectedMux`.

## Source
The vulnerability exists in `settings_routes.go` line 7:
```
apiMux.HandleFunc("/settings/email", handler.UpdateEmail)
```

The `UpdateEmail` handler (settings_handler.go) accepts POST requests and modifies user state via `r.FormValue("email")`. By registering this endpoint on `apiMux` instead of `protectedMux`, requests lack CSRF token validation.

## Fix
Move the `/settings/email` route registration from `apiMux` to `protectedMux`:

```go
func RegisterSettingsRoutes(protectedMux *http.ServeMux, apiMux *http.ServeMux, handler *SettingsHandler) {
	protectedMux.HandleFunc("/settings/profile", handler.Profile)
	protectedMux.HandleFunc("/settings/email", handler.UpdateEmail)
}
```

This ensures the endpoint receives CSRF middleware protection alongside other sensitive operations.

## Explanation
The root cause is architectural inconsistency: state-changing endpoints must be registered on the protected mux to receive CSRF token validation. The `UpdateEmail` handler accepts `POST` requests and uses `r.FormValue()` to extract user input, then performs an account modification—a privileged operation vulnerable to CSRF attacks.

An attacker can exploit this by embedding a form on an external site. When a logged-in user visits that site, their browser automatically sends authenticated cookies, causing an unwanted email change without the user's knowledge or consent.

The fix restores consistency by colocating both sensitive operations (`/settings/profile` and `/settings/email`) on the protected mux, ensuring both receive CSRF token validation as a prerequisite to state modification.
