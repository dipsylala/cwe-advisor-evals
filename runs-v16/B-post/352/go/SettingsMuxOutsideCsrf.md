## Verdict

Confirmed CSRF vulnerability. The state-changing handler `UpdateEmail` is registered on an unprotected mux (`apiMux`), bypassing CSRF protection that should guard all authenticated state changes.

## Source

An unauthenticated attacker on a different origin. The attacker crafts a malicious web page containing a form or script that targets the vulnerable endpoint. When a logged-in user visits the attacker's page, the browser automatically includes session cookies in the cross-origin request, allowing the attacker to perform state changes on the user's behalf.

## Fix

Move the registration of `handler.UpdateEmail` from `apiMux` to `protectedMux` on line 7 of `settings_routes.go`:

**Before (vulnerable):**
```go
func RegisterSettingsRoutes(protectedMux *http.ServeMux, apiMux *http.ServeMux, handler *SettingsHandler) {
	protectedMux.HandleFunc("/settings/profile", handler.Profile)
	apiMux.HandleFunc("/settings/email", handler.UpdateEmail)
}
```

**After (fixed):**
```go
func RegisterSettingsRoutes(protectedMux *http.ServeMux, apiMux *http.ServeMux, handler *SettingsHandler) {
	protectedMux.HandleFunc("/settings/profile", handler.Profile)
	protectedMux.HandleFunc("/settings/email", handler.UpdateEmail)
}
```

## Explanation

The vulnerability exists because `handler.UpdateEmail` performs a state-changing operation (queuing an email change via `h.Service.QueueEmailChange()`) but is registered on `apiMux`, an unprotected `http.ServeMux`. The `protectedMux` parameter is presumably wrapped with CSRF middleware (as evidenced by its name and context), while `apiMux` is not. By moving the registration to `protectedMux`, the CSRF middleware will intercept the request and validate the CSRF token before the handler executes. This ensures only requests with a valid, session-bound CSRF token can trigger the email change, blocking forged cross-site requests.

The Go language-specific guidance requires that "every handler that mutates state is registered on the CSRF-wrapped router, not a separate `http.ServeMux` or parallel API mux."

## Behaviour changes

- The `/settings/email` endpoint now requires a valid CSRF token in requests, matching the protection applied to `/settings/profile` and other protected routes.
- Forged cross-origin POST requests to `/settings/email` will be rejected by the CSRF middleware with an HTTP 403 Forbidden response.
- Legitimate clients (forms, AJAX handlers) must obtain a CSRF token from the server and include it in their requests to successfully update the email. This is transparent to properly implemented clients that use the framework's token generation and validation mechanisms.
- The email change operation remains functionally identical when a valid token is present; the change is purely in which mux handles the request.
