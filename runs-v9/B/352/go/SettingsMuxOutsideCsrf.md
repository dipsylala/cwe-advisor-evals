## Verdict

exploitable (confidence: medium)

## Source

Incoming HTTP `POST /settings/email` request, routed through `apiMux` (`RegisterSettingsRoutes`, `settings_routes.go:7`) to `SettingsHandler.UpdateEmail` (`settings_handler.go:13`). The handler checks only that the method is `POST` (line 14-17) and reads the new address with `email := r.FormValue("email")` (line 19) - no CSRF token, `Origin`/`Referer` allowlist check, or other authenticity check is performed anywhere on this path.

## Fix

Vulnerable (`settings_routes.go`):

```go
package settingscsrf

import "net/http"

func RegisterSettingsRoutes(protectedMux *http.ServeMux, apiMux *http.ServeMux, handler *SettingsHandler) {
	protectedMux.HandleFunc("/settings/profile", handler.Profile)
	apiMux.HandleFunc("/settings/email", handler.UpdateEmail) // state-changing handler registered on the mux that is not CSRF-protected
}
```

Fixed (`settings_routes.go`):

```go
package settingscsrf

import "net/http"

func RegisterSettingsRoutes(protectedMux *http.ServeMux, apiMux *http.ServeMux, handler *SettingsHandler) {
	protectedMux.HandleFunc("/settings/profile", handler.Profile)
	protectedMux.HandleFunc("/settings/email", handler.UpdateEmail)
}
```

## Explanation

`UpdateEmail` performs a state change (queuing an email address update via `SettingsService.QueueEmailChange`) but was registered on `apiMux` instead of `protectedMux`, so it sits outside whatever CSRF protection wraps the protected router - the handler itself validates only the HTTP method, never a token or request origin. Per the Go CSRF guidance, every state-changing handler must be registered on the CSRF-wrapped router rather than a separate mux, since a parallel mux is a common way protection gets silently bypassed for a subset of routes. Moving the `/settings/email` registration onto `protectedMux` puts the handler behind the same CSRF enforcement already applied to `/settings/profile`, so a forged cross-site `POST` to `/settings/email` is rejected before `UpdateEmail` runs. This change is confined to routing; `UpdateEmail`'s method check, form parsing, and call into `SettingsService.QueueEmailChange` are untouched, and the fix assumes - based on the naming pattern and the absence of any other CSRF wiring in the three files provided - that `protectedMux` is the router already wrapped with CSRF middleware elsewhere in the application; that wiring itself was not visible in the files reviewed.

## Behaviour changes

- Routing only: `/settings/email` moves from `apiMux` to `protectedMux`. No change to `UpdateEmail`'s logic, method check, response codes, or to `SettingsService.QueueEmailChange`'s signature or behavior.
- If `protectedMux` is wrapped with CSRF middleware elsewhere in the application (assumed, not visible in the reviewed files), requests to `/settings/email` that lack a valid CSRF token will now be rejected (typically `403 Forbidden`) before reaching the handler; legitimate same-site requests carrying a valid token are unaffected.
- `apiMux` no longer registers any route in this file. If `apiMux` is used elsewhere for non-browser or token/API-key-authenticated clients that cannot supply a CSRF token, this move would require those callers to authenticate through the protected path instead - this was not observable in the three files reviewed and should be confirmed against the rest of the routing setup before merging.
