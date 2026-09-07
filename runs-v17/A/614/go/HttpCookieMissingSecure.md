## Verdict

**CONFIRMED**: The code sets a sensitive session cookie without the `Secure` attribute, allowing it to be transmitted over unencrypted HTTP connections in addition to HTTPS. This violates CWE-614 and exposes the session token to interception.

## Source

File: HttpCookieMissingSecure.go, lines 20–24

```go
http.SetCookie(w, &http.Cookie{
	Name:  "session_token",
	Value: sessionToken,
	Path:  "/",
})
```

The `http.Cookie` struct is missing the `Secure: true` field, which means the cookie will be sent over both HTTP and HTTPS connections. Since this cookie holds a sensitive session token obtained from authentication, it must be restricted to HTTPS only.

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
		Name:   "session_token",
		Value:  sessionToken,
		Path:   "/",
		Secure: true,
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

The fix adds `Secure: true` to the `http.Cookie` struct. The `Secure` attribute instructs the browser to send the cookie only over HTTPS connections, preventing it from being transmitted over unencrypted HTTP.

In Go's `net/http` package, cookies are created via the `http.Cookie` type. Setting `Secure: true` ensures that even if an attacker lures the user to an HTTP version of the site, the sensitive session token will not be sent, protecting it from network-layer interception. This is a primary defence for session token confidentiality in HTTPS contexts.

The session token is returned directly from the authentication function and is sensitive data that must be protected during transport. Adding the `Secure` attribute completes the cookie configuration for production use.
