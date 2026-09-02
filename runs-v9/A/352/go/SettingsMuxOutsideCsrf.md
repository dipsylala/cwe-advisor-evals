## Verdict

Confirmed. `UpdateEmail` is a state-changing, cookie/session-authenticated POST endpoint that is registered on `apiMux` instead of `protectedMux`, so it is served outside whatever CSRF defense wraps the protected router. A cross-site form or fetch that induces an authenticated user's browser to POST to `/settings/email` will have its request processed and the user's email queued for change, with no CSRF token check in the call chain.

## Source

`E:/Github/cwe-advisor/evals/cases/352/go/SettingsMuxOutsideCsrf/settings_routes.go`, line 7:

```go
apiMux.HandleFunc("/settings/email", handler.UpdateEmail)
```

`RegisterSettingsRoutes` is handed two distinct `*http.ServeMux` values, `protectedMux` and `apiMux`. The naming and the sibling registration on line 6 (`protectedMux.HandleFunc("/settings/profile", handler.Profile)`) make clear that `protectedMux` is the router intended to carry session-based auth and its associated CSRF middleware, while `apiMux` is a separate router (typically reserved for token-authenticated, non-browser API clients that don't carry ambient cookies and so don't need CSRF checks). `UpdateEmail` in `settings_handler.go` reads `email` from `r.FormValue` and calls `h.Service.QueueEmailChange`, i.e. it performs a real account mutation driven by a same-origin-looking POST body, exactly the shape that needs CSRF protection when reached via cookie auth. Registering it on `apiMux` instead of `protectedMux` is what puts the state-changing operation outside the CSRF boundary.

## Fix

Register the email-update route on `protectedMux`, alongside `Profile`, so it is subject to the same CSRF enforcement as the rest of the authenticated settings surface:

```go
package settingscsrf

import "net/http"

func RegisterSettingsRoutes(protectedMux *http.ServeMux, apiMux *http.ServeMux, handler *SettingsHandler) {
	protectedMux.HandleFunc("/settings/profile", handler.Profile)
	protectedMux.HandleFunc("/settings/email", handler.UpdateEmail)
}
```

If `apiMux` is retained elsewhere for genuinely token-authenticated clients (e.g. a bearer-token API that never sends the session cookie), keep it that way and do not add cookie-based session handling to it; if `apiMux` in this codebase is in fact wrapped with the same or an equivalent CSRF middleware as `protectedMux`, confirm that at the point the two muxes are constructed (not shown in this call chain) — but the safer and simplest fix, consistent with the router names already chosen by this code, is to serve this cookie-authenticated, state-changing endpoint from `protectedMux`.

As defense in depth, `UpdateEmail` should also verify the CSRF token itself (or rely on middleware that rejects the request before the handler runs) rather than trusting mux placement alone, and should require re-authentication or a confirmation step for a sensitive action like an email-address change, since a changed email can be a stepping stone to full account takeover via password reset.

## Explanation

CSRF protection in a Go `net/http` service is commonly applied by wrapping a `*http.ServeMux` with middleware (e.g. `gorilla/csrf` or an equivalent handler) that validates a per-session token on unsafe methods before the underlying handler runs. That protection is a property of the mux/middleware chain a route is registered on, not of the handler function itself — the same `handler.UpdateEmail` value would be protected if reached through `protectedMux` and unprotected if reached through `apiMux`. Because `RegisterSettingsRoutes` wires `UpdateEmail` to `apiMux` while `Profile` (a read-only, side-effect-free GET) goes to `protectedMux`, the split has been made backwards from a security standpoint: the harmless endpoint sits behind CSRF checks and the state-changing one does not. An attacker hosting a page with an auto-submitting form (`<form method="POST" action="https://target/settings/email">`) or a `fetch` with `credentials: 'include'` can trigger this handler in the victim's authenticated session purely from cross-site context, since nothing in the call chain requires a token the attacker's page could not also supply. Moving the registration to `protectedMux` restores the intended CSRF boundary without any change to `SettingsHandler` or `SettingsService`.
