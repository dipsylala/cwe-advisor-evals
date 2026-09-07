## Verdict
exploitable

## Source
Cross-origin HTTP POST request to `/settings/email` endpoint

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

The vulnerability exists on settings_routes.go line 7, where the email update handler is registered on `apiMux` (an unprotected, parallel HTTP mux) instead of `protectedMux` (the CSRF-protected router). The UpdateEmail handler accepts POST requests that perform a state-changing operation: it extracts an email address from form data and queues it for modification via `QueueEmailChange()`. Without CSRF protection, an attacker can craft a forged cross-site request to change an authenticated victim's email address. The fix moves the handler registration from `apiMux` to `protectedMux`, ensuring that state-changing operations are guarded by CSRF token validation before any business logic executes. This aligns the email update handler with the same protection applied to the Profile endpoint.

## Behaviour changes

None. The fix moves the route registration to the protected mux without changing the handler's method signature, parameters, or return value. The handler still accepts the same POST requests and processes them through the same business logic; the only change is the addition of CSRF token validation by the protected router middleware.
