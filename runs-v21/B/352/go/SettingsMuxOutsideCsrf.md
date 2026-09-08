## Verdict

Exploitable. The state-changing handler `UpdateEmail` processes POST requests that queue an email change without CSRF token validation. The handler is registered on `apiMux` (line 7 of settings_routes.go), which is not wrapped with CSRF protection middleware, whereas the `protectedMux` parameter is passed explicitly to receive protected routes. The vulnerability allows attackers to forge cross-site requests that modify user email addresses.

## Source

HTTP POST request to `/settings/email` with attacker-controlled email parameter obtained via `r.FormValue("email")` in the `UpdateEmail` handler (settings_handler.go line 11).

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

The vulnerability exists because the state-changing handler `UpdateEmail` was registered on `apiMux` instead of `protectedMux`. This places the handler outside the scope of CSRF protection middleware that guards the main router. Moving the handler registration to `protectedMux` ensures it receives CSRF token validation on every state-changing request, preventing attackers from forging cross-site POST requests to change user email addresses. The handler logic itself remains unchanged; only its registration point moves to the protected router.

## Behaviour changes

None. The handler's signature, logic, and response behavior remain identical. The only change is the route is now served from `protectedMux` instead of `apiMux`, meaning it now receives CSRF middleware protection that was previously absent. This is the intended fix and restores correct security posture without altering legitimate request handling.
