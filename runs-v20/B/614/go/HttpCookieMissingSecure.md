## Verdict

exploitable

- CWE ID: CWE-614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute)
- Location: `HttpCookieMissingSecure.go`, line 20 (the `http.SetCookie(w, &http.Cookie{...})` call)
- Confidence: high

## Source

`loginHandler` builds the cookie's value from `sessionToken`, the return value of `authenticate(username, password)` at line 13 - a server-issued session token, not attacker-controlled input. The vulnerability is not in the token's provenance but in how the cookie carrying it is constructed: the `http.Cookie{}` literal passed to `http.SetCookie` at line 20 sets `Name`, `Value`, and `Path` only, leaving `Secure`, `HttpOnly`, and `SameSite` at their zero values (`false`, `false`, unset). This is a single-file, single-function case: source and sink sit in the same handler with no intermediate hops.

## Fix

### File: HttpCookieMissingSecure.go

```go
package main

import (
	"net/http"
)

// loginHandler authenticates the user and issues a session cookie holding
// the session token returned by the login form.
func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	sessionToken, ok := authenticate(username, password)
	if !ok {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	w.WriteHeader(http.StatusOK)
}

func authenticate(username, password string) (string, bool) {
	if username == "" || password == "" {
		return "", false
	}
	return "tok-" + username, true
}
```

## Explanation

The `http.Cookie{}` literal at the sink now sets `Secure: true`, so the browser will only send `session_token` back over HTTPS, closing the CWE-614 finding. `HttpOnly: true` and `SameSite: http.SameSiteStrictMode` were added alongside it per the loaded Go guidance, which treats all three as the standard hardening set for a session cookie set in the same call (`HttpOnly` blocks `document.cookie` access as defense-in-depth against XSS exfiltration, and an explicit `SameSite` avoids relying on browser-default cross-site behavior) rather than a partial fix that leaves the other two attributes unset. `Secure` is set unconditionally rather than derived from `r.TLS` or a forwarded-proto header, per the guidance's note that `r.TLS` reflects only the last hop and is unreliable behind a reverse proxy; TLS termination in front of the app is assumed to enforce HTTPS. `SameSiteStrictMode` was chosen over `LaxMode` because this handler is a same-origin login POST with no indication in the code of an external redirect or SSO/OAuth callback flow that `Strict` would break; if the application does link into an authenticated page from external referrers or third-party redirects, `LaxMode` should be used instead.

## Behaviour changes

- Added `Secure: true`, `HttpOnly: true`, `SameSite: http.SameSiteStrictMode` to the `http.Cookie{}` literal. Reason: these are exactly the fields the CWE-614 finding and the loaded Go guidance require; `Name`, `Value`, and `Path` are unchanged. `HttpOnly` and `SameSite` go beyond the literal `Secure`-only finding but are prescribed by the same guidance entry as the standard set for a sensitive session cookie set at this call site, not separately-sourced hardening.
- Functional consequence: the cookie will no longer be sent by the browser over a plain-HTTP connection, and will no longer be attached to cross-site requests (including top-level cross-site navigations) due to `SameSite=Strict`. If the deployment does not terminate TLS in front of the app, or if a legitimate cross-site entry point to an authenticated route exists, those need separate verification - the fix assumes HTTPS is enforced site-wide (per the guidance's explicit precondition for `Secure`) and that no cross-site flow depends on this cookie.
- No change to `authenticate()`, `loginHandler`'s parameters, return behavior, error handling, or the discarded/returned values at the sink - the fix is scoped to the cookie's attribute set.

Verification: `go vet ./...` run against the fixed file in a scratch directory (with a throwaway `go.mod` added only for the check) returned no diagnostics. `SameSiteStrictMode` is `net/http`'s standard-library constant (`http.SameSiteStrictMode`), used per the loaded `cwe/614/go/INDEX.md` guidance; no new import or third-party dependency was introduced.

Assumption: `SameSiteStrictMode` was chosen over `LaxMode` based on the absence of any cross-site entry flow in the visible code (per the guidance's "choose `Strict` or `Lax` per flow" principle); if the real application has an SSO/OAuth callback or external-link entry point into this session, `LaxMode` is the correct choice instead. This lowers confidence on that one attribute only; the `Secure` and `HttpOnly` additions are not affected by this assumption.
