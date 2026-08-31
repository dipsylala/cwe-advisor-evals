## Verdict

Confirmed. `loginHandler` issues the `session_token` session cookie via `http.SetCookie` without setting `Secure` (and also without `HttpOnly`/`SameSite`), so the session token can be sent by the browser over a plaintext HTTP connection and is exposed to network attackers (e.g. on shared Wi-Fi or via SSL-stripping) even if the site is normally served over HTTPS.

## Source

- File: `HttpCookieMissingSecure.go`
- `sessionToken` returned by `authenticate(username, password)` at line 13.
- Sink: `http.SetCookie(w, &http.Cookie{...})` at line 20, where `sessionToken` is placed in the cookie's `Value` field without `Secure: true`.

## Fix

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

`http.Cookie`'s `Secure` field defaults to `false` (unset), so Go's `net/http` sends the cookie on both HTTP and HTTPS requests unless `Secure: true` is set explicitly. Adding `Secure: true` instructs the browser to only ever transmit `session_token` over an encrypted connection, closing the plaintext-exposure path this cookie carries a session identifier over.

While remediating this specific cookie, two closely related hardenings were also applied since they cost nothing to add at the same call site and address adjacent risks for the same session token: `HttpOnly: true` prevents the cookie from being read by client-side JavaScript (mitigating token theft via XSS), and `SameSite: http.SameSiteLaxMode` restricts the cookie from being sent on most cross-site requests (mitigating CSRF). These are defense-in-depth additions alongside the primary fix, not the finding itself — the reported issue is the missing `Secure` attribute, and setting it is what remediates it.

No behavioral change occurs for legitimate use as long as the application is served over HTTPS in production; if the handler is exercised locally over plain HTTP during development, the cookie will no longer be set/sent on that connection, which is expected and correct.
