## Verdict

Confirmed. `loginHandler` issues the `session_token` session cookie via `http.SetCookie` without setting `Secure` (or `HttpOnly`/`SameSite`), so the browser will send the session token over a plaintext HTTP connection if one is ever made to the host, exposing it to network eavesdroppers.

## Source

`E:/Github/cwe-advisor/evals/cases/614/go/HttpCookieMissingSecure/HttpCookieMissingSecure.go`, line 20-24:

```go
http.SetCookie(w, &http.Cookie{
    Name:  "session_token",
    Value: sessionToken,
    Path:  "/",
})
```

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

`http.Cookie`'s `Secure` field defaults to `false` (Go's `net/http` never sets it implicitly), so the cookie as originally written is sent over both HTTP and HTTPS. Setting `Secure: true` instructs the browser to attach the cookie only on connections made over HTTPS, closing the network-eavesdropping vector the finding flags.

Since this cookie carries a session token, two defense-in-depth attributes are added alongside the required fix rather than as a substitute for it:

- `HttpOnly: true` blocks access to the cookie from JavaScript (`document.cookie`), limiting the damage an XSS finding elsewhere in the app could do to this specific token.
- `SameSite: http.SameSiteLaxMode` stops the cookie from being attached to most cross-site requests, mitigating CSRF use of the session token. `Lax` is chosen over `Strict` because `Strict` would also drop the cookie on top-level navigations arriving from an external link (e.g. a user clicking a bookmarked or emailed link into the app), which is usually not the desired behavior for a session cookie; `Lax` still blocks the cross-site POST/state-changing request pattern CSRF relies on.

No other behavior changes: the cookie's name, value, and path are untouched, so existing clients reading `session_token` continue to work identically over HTTPS.
