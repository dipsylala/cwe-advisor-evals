## Verdict

Exploitable. The `http.SetCookie()` call at line 20 creates a session cookie carrying a sensitive authentication token but omits the `Secure`, `HttpOnly`, and `SameSite` attributes. Without `Secure`, the cookie can be transmitted over unencrypted HTTP connections, exposing the session token to network interception. Without `HttpOnly`, the cookie is accessible to JavaScript, widening the attack surface to XSS vulnerabilities.

## Source

The vulnerability originates in the `authenticate()` function (line 29), which returns a session token (`"tok-" + username`). This token is passed to `http.SetCookie()` at line 20 without enforcing HTTPS-only transmission.

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
		SameSite: http.SameSiteLaxMode,
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

The fix adds three security attributes to the `http.Cookie` struct:

1. **`Secure: true`** enforces HTTPS-only transmission. The browser will only send the cookie over encrypted connections, preventing interception over unencrypted HTTP.

2. **`HttpOnly: true`** prevents JavaScript from accessing the cookie via `document.cookie`. This blocks XSS attacks from reading the session token even if attacker-controlled script is injected into the page.

3. **`SameSite: http.SameSiteLaxMode`** provides CSRF protection by restricting when the cookie is sent in cross-site requests. `Lax` mode includes the cookie in same-site navigation and form submissions from external sites, but not in cross-site image loads or XHR requests, balancing security with usability for SSO flows.

These attributes are mandatory for any cookie carrying authentication or session data in Go. The underlying protocol negotiation and HTTPS enforcement at the infrastructure level must be in place for `Secure` to function; the application cannot conditionally set `Secure` based on `r.TLS` when behind a reverse proxy.

## Behaviour changes

None. The fix does not alter the return value, the control flow, or the cookie's functional contract. The cookie is still set once per login, carries the same token value, and follows the same path (`"/"`). The only difference is that the browser will enforce the three security constraints at transmission time.

Client code that was exploiting the unprotected cookie over HTTP will no longer receive it, which is the intended behavior change for security—such requests represent a deployment configuration error (absence of HTTPS enforcement) rather than correct application behavior.
