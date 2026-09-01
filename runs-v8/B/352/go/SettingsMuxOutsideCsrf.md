## Verdict

Confirmed. The `UpdateEmail` handler at line 13 of `settings_handler.go` performs state-changing operations (queue email change) but is registered on an unprotected mux, creating a CSRF vulnerability.

## Source

HTTP POST request to `/settings/email` containing form parameter `email`, received by `UpdateEmail` handler via `r.FormValue("email")`.

## Fix

```go
func RegisterSettingsRoutes(protectedMux *http.ServeMux, apiMux *http.ServeMux, handler *SettingsHandler) {
	protectedMux.HandleFunc("/settings/profile", handler.Profile)
	protectedMux.HandleFunc("/settings/email", handler.UpdateEmail)
}
```

Change line 7 from:
```
	apiMux.HandleFunc("/settings/email", handler.UpdateEmail)
```

To:
```
	protectedMux.HandleFunc("/settings/email", handler.UpdateEmail)
```

## Explanation

The `UpdateEmail` handler accepts POST requests and mutates state by queuing an email change, but was registered on `apiMux`, an unprotected mux. Registering it on `protectedMux` ensures that the handler is wrapped by CSRF protection middleware, preventing attackers from forcing state-changing requests through forged cross-site calls. The state-changing operation (`QueueEmailChange`) is now protected by the CSRF-guarded router, which validates cross-origin requests before allowing the handler to execute.

## Behaviour changes

Requests to `/settings/email` are now subject to CSRF validation by the protected router. Legitimate requests from the application's own forms/AJAX will succeed (they include valid CSRF tokens or pass Fetch metadata validation). Cross-site requests from attacker-controlled pages will be rejected with `http.StatusForbidden` before reaching the handler.
