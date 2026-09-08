## Verdict

Confirmed. `/settings/email` is a state-changing `POST` handler (`SettingsHandler.UpdateEmail`, which calls `SettingsService.QueueEmailChange`) registered on `apiMux`, a router that is separate from `protectedMux`. Nothing in the call chain wraps `apiMux` with CSRF protection, so a cross-site form or fetch can submit to `/settings/email` using the victim's ambient session cookie and change their email address. The safe, side-effect-free `Profile` handler is correctly registered on `protectedMux`; the mutating `UpdateEmail` handler is the one that ends up on the unprotected mux.

## Source

`http.Request` reaching `SettingsHandler.UpdateEmail` at `settings_handler.go:13-22`, specifically `r.FormValue("email")` at line 19 - browser-submitted, attacker-triggerable via a forged cross-site form post.

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

The three files show two parallel muxes passed into `RegisterSettingsRoutes`: `protectedMux` and `apiMux`. The state-changing `UpdateEmail` handler was registered on `apiMux` instead of `protectedMux`, so any CSRF middleware wrapping `protectedMux` elsewhere in the application (implied by its name and by `Profile` being registered there) never sees requests to `/settings/email`. This matches the knowledge base's core CWE-352 guidance for Go: "Ensure every handler that mutates state is registered on the CSRF-wrapped router, not a separate `http.ServeMux` or parallel API mux." The fix is a one-line change confined to the visible taint sink: move the `/settings/email` registration from `apiMux` to `protectedMux`, so the mutating handler is reachable only through whatever CSRF protection (`net/http.CrossOriginProtection`, `filippo.io/csrf/gorilla`, or equivalent middleware) already guards `protectedMux`. No token-issuance or middleware-wrapping code is visible in this call chain, so this change does not itself add a CSRF check - it corrects the routing defect that was routing the mutating endpoint around whatever check exists. `UpdateEmail`'s existing `r.Method != http.MethodPost` guard, its return codes, and `SettingsService.QueueEmailChange`'s signature and behavior are all unchanged.

Checked: copied the three files to a scratch Go module and ran `go vet ./...` and `go build ./...` against the fixed `settings_routes.go` plus the unmodified `settings_handler.go` and `settings_service.go`; both completed cleanly (exit 0). `apiMux` remains an unused parameter in `RegisterSettingsRoutes`, which is legal in Go (unlike an unused local variable or import) and preserves the function's exported signature for any caller outside this call chain.

## Behaviour changes

- `/settings/email` is no longer served from `apiMux`; it moves to `protectedMux`. Any caller that reached this endpoint through `apiMux`'s network exposure, port, middleware chain, or authentication mechanism (if different from `protectedMux`'s) will need to reach it through `protectedMux` instead. This call chain does not show how the two muxes differ in exposure or auth, so confirm before deploying that `protectedMux` is reachable by the same legitimate clients (browser sessions with a valid CSRF token) that previously used `apiMux` for this route.
- No change to `UpdateEmail`'s method check, response codes, or `QueueEmailChange`'s behavior.
