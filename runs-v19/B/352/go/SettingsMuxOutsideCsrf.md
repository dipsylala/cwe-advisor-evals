## Verdict
exploitable

## Source
Cross-site attacker-initiated HTTP POST request to `/settings/email`

## Fix

### File: settings_routes.go
```go
package settingscsrf

import "net/http"

func RegisterSettingsRoutes(protectedMux *http.ServeMux, apiMux *http.ServeMux, handler *SettingsHandler) {
	protectedMux.HandleFunc("/settings/profile", handler.Profile)
	protectedMux.HandleFunc("/settings/email", handler.UpdateEmail)
}
```

## Explanation
The `UpdateEmail` handler is a state-changing operation (POST method that modifies the user's email via `h.Service.QueueEmailChange()`). In the original code, this handler was registered on `apiMux`, which is an unprotected `http.ServeMux` separate from the CSRF-protected `protectedMux`. The Go CSRF guidance explicitly forbids registering state-changing handlers on separate, unprotected muxes: "Ensure every handler that mutates state is registered on the CSRF-wrapped router, not a separate http.ServeMux or parallel API mux." The fix moves the handler registration from `apiMux.HandleFunc()` to `protectedMux.HandleFunc()`, ensuring the handler is wrapped by CSRF middleware. This closes the CSRF vulnerability by guaranteeing token validation before the state change is processed.

## Behaviour changes
none
