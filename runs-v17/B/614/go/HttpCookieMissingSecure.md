## Verdict

Exploitable. The `http.SetCookie()` call at line 20-24 sets a session token cookie without the `Secure`, `HttpOnly`, and `SameSite` attributes, allowing the cookie to be transmitted over unencrypted HTTP connections and accessed by JavaScript. An attacker on the network path can intercept the cookie over HTTP and impersonate the user.

## Source

Line 13: `sessionToken, ok := authenticate(username, password)` returns a sensitive session token string from the `authenticate()` function. This value is fresh and attacker-controlled in the sense that the server generates it based on the login request.

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

The fix adds three cookie security attributes to enforce secure transmission of the session token. `Secure: true` restricts the cookie to HTTPS-only transmission, preventing interception over unencrypted HTTP. `HttpOnly: true` blocks JavaScript access via `document.cookie`, mitigating cross-site scripting attacks that could steal the session token. `SameSite: http.SameSiteLaxMode` provides CSRF protection by restricting the cookie to same-site requests, with an exception for top-level navigations (which is appropriate for login flows). These attributes work together to ensure the session token is transmitted only over secure channels and is resistant to common web attacks.

## Behaviour changes

The cookie will now:
1. Transmit only over HTTPS connections (Secure flag enforcement)
2. Remain inaccessible to JavaScript running on the page (HttpOnly flag enforcement)
3. Only be sent in same-site requests except for top-level navigation links (SameSite=Lax enforcement)

These are security enhancements that do not alter the application's login logic or functionality—the cookie still carries the same session token to the same path and domain. The changes enforce secure transport and restrict unintended use of the session token by scripts or cross-site requests, but the core session mechanism remains unchanged. The application should already be enforcing HTTPS in production as a prerequisite for CWE-614 remediation; these attributes ensure the browser rejects any attempt to set or transmit the cookie over unencrypted connections.
