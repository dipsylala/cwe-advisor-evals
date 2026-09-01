## Verdict

VULNERABLE. The `UpdateEmail` handler performs a state-changing operation but is registered on an unprotected mux outside the CSRF-protected scope.

## Source

Line 7 in `settings_routes.go` registers the `UpdateEmail` handler on `apiMux`:

```go
apiMux.HandleFunc("/settings/email", handler.UpdateEmail)
```

The `UpdateEmail` handler (in `settings_handler.go`, lines 13-22) accepts POST requests and modifies application state by reading form data and calling `h.Service.QueueEmailChange()`. This state-changing endpoint must be protected by CSRF token validation but is instead registered on a mux outside the protected scope.

## Fix

Register the `UpdateEmail` handler on `protectedMux` instead of `apiMux`:

```go
func RegisterSettingsRoutes(protectedMux *http.ServeMux, apiMux *http.ServeMux, handler *SettingsHandler) {
	protectedMux.HandleFunc("/settings/profile", handler.Profile)
	protectedMux.HandleFunc("/settings/email", handler.UpdateEmail)
}
```

The state-changing `UpdateEmail` endpoint must use the CSRF-protected mux to ensure incoming requests carry valid CSRF tokens before the email change is processed.

## Explanation

CWE-352 CSRF requires that state-changing operations verify a CSRF token to confirm the request originates from the user's own session, not from an attacker-controlled page. The vulnerable code splits routes between two muxes: a protected one and an unprotected one. The `/settings/email` endpoint modifies user state via `QueueEmailChange()` but is registered on the unprotected mux, leaving it open to cross-site forgery attacks. Moving it to the protected mux ensures CSRF token validation occurs before the email change proceeds.
