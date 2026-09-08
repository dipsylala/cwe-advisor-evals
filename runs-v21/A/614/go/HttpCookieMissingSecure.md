## Verdict
CONFIRMED: CWE-614 session cookie missing Secure attribute, allowing transmission over unencrypted HTTP.

## Source
File: HttpCookieMissingSecure.go, lines 20–24. The loginHandler creates an http.Cookie for storing a session token but omits the Secure flag, permitting the cookie to be transmitted over non-HTTPS connections.

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

	// SAST FINDING: CWE-614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute) reported here. Sink is the next statement.
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
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
The fix adds two security attributes to the session cookie:

**Secure: true** — Restricts the cookie to HTTPS-only transmission, preventing interception over unencrypted HTTP connections. This directly addresses CWE-614.

**HttpOnly: true** — As a defense-in-depth measure, prevents JavaScript from accessing the session token, mitigating XSS-based session theft. This is standard practice for sensitive session cookies.

The session token is now transmitted only over encrypted connections and inaccessible to client-side scripts.
