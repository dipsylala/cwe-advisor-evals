## Verdict

The `UpdateEmail` endpoint performs a state-changing operation (email modification) but is registered on an unprotected HTTP mux instead of the CSRF-protected mux, leaving it vulnerable to cross-site request forgery attacks.

## Source

The vulnerability exists in the route registration:
- `settings_routes.go` line 7: The `/settings/email` route is registered on `apiMux`, which lacks CSRF protection
- `settings_handler.go` lines 13-22: The `UpdateEmail` handler accepts POST requests and modifies user state via `QueueEmailChange`
- `settings_service.go` line 7: The service processes the email change without CSRF validation

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

The route registration was placing the state-changing `/settings/email` endpoint on `apiMux`, which is an unprotected HTTP mux without CSRF token validation. By moving the handler registration to `protectedMux` on line 7, the endpoint now benefits from CSRF protection mechanisms that the protected mux provides (typically via middleware that validates CSRF tokens on state-changing requests).

The fix is minimal: change `apiMux` to `protectedMux` for the UpdateEmail handler registration. This ensures that POST requests modifying user email are subject to CSRF token validation, preventing attackers from forging requests that would change a user's email through their browser.
