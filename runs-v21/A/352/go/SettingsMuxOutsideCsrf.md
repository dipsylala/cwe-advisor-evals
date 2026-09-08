## Verdict
VULNERABLE

## Source
The UpdateEmail handler at line 7 of settings_routes.go is registered on `apiMux` instead of `protectedMux`. The UpdateEmail handler modifies sensitive user data (email address) via POST requests but lacks CSRF token protection because it is routed through an unprotected mux.

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
The vulnerability stems from routing a state-modifying endpoint (UpdateEmail) through an unprotected mux (apiMux) instead of the CSRF-protected mux (protectedMux). The UpdateEmail handler accepts POST requests and calls QueueEmailChange, which modifies the user's email address—a sensitive operation that requires CSRF token validation.

The fix moves the `/settings/email` route registration from `apiMux` to `protectedMux` on line 7, ensuring the handler benefits from CSRF protection mechanisms applied to the protected mux. This aligns with the Profile handler on line 6 which is already correctly routed through the protected mux.
