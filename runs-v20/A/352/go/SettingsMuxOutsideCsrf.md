## Verdict

Confirmed. `RegisterSettingsRoutes` registers the state-changing endpoint on the wrong mux.

## Source

`r.FormValue("email")` in `SettingsHandler.UpdateEmail` (settings_handler.go) - attacker-controlled form data submitted by the victim's browser.

## Fix

The application clearly runs two muxes: `protectedMux`, which carries the CSRF-covering middleware chain, and `apiMux`, which does not (it is meant for endpoints that are not driven by an authenticated browser session, such as token-authenticated API clients). `UpdateEmail` is a state-changing, cookie-session-authenticated, form-submitted action - exactly what CSRF protection must cover - but it is wired onto `apiMux`, so it never passes through the CSRF check that `protectedMux` applies. Any third-party page can trigger a cross-origin `POST /settings/email` from a logged-in victim's browser and change their email unattended.

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

`protectedMux` and `apiMux` are separate `http.ServeMux` instances passed in by the caller specifically so that different middleware chains can wrap them - the naming and the split itself only make sense if `protectedMux` is the one wrapped with session/CSRF middleware before being mounted. `/settings/email` is a `POST` handler that mutates account state (`QueueEmailChange`) based on nothing but form data and the ambient session, which is the textbook CSRF target. Registering it on `apiMux` instead of `protectedMux` takes it out of whatever CSRF check the protected chain applies, while the harmless read-only `/settings/profile` GET stayed on the correct mux - a strong signal the split was accidental rather than intentional.

The fix moves `UpdateEmail`'s registration onto `protectedMux`, the same mux `Profile` uses, so the mutating endpoint is covered by the same CSRF-protecting middleware chain as the rest of the authenticated settings surface. No change to `settings_handler.go` or `settings_service.go` is needed: the vulnerability is entirely in which mux the route was attached to, not in the handler logic itself.
