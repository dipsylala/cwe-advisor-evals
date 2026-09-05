## Verdict

Exploitable. The `http.SetCookie()` call on line 20 sets a session token cookie without the `Secure` attribute, allowing it to be transmitted over unencrypted HTTP connections where an attacker can intercept it.

## Source

The session token returned by `authenticate(username, password)` on line 13, which is a security-sensitive authentication credential.

## Fix

```go
// Vulnerable code
http.SetCookie(w, &http.Cookie{
	Name:  "session_token",
	Value: sessionToken,
	Path:  "/",
})

// Fixed code
http.SetCookie(w, &http.Cookie{
	Name:     "session_token",
	Value:    sessionToken,
	Path:     "/",
	Secure:   true,
	HttpOnly: true,
	SameSite: http.SameSiteLaxMode,
})
```

## Explanation

The fix adds three security attributes to the cookie. `Secure: true` ensures the cookie is only transmitted over HTTPS, preventing interception over unencrypted connections. `HttpOnly: true` prevents the cookie from being accessed by client-side JavaScript, mitigating XSS attacks that could steal the session token. `SameSite: http.SameSiteLaxMode` provides CSRF protection by restricting when the cookie is sent in cross-site requests while still allowing it on top-level navigations needed for normal authentication flows.

## Behaviour changes

Three new cookie attributes are set:
- `Secure: true` — enforces HTTPS-only transmission; requires the application to be served over HTTPS or the browser will reject the cookie
- `HttpOnly: true` — prevents JavaScript access via `document.cookie`, blocking one vector for session hijacking
- `SameSite: http.SameSiteLaxMode` — restricts cross-site cookie transmission but allows the cookie to be sent on top-level navigations, which is appropriate for a session cookie that needs to work with normal login flows

These changes have no impact on the cookie's core function (identifying the session) or its lifetime; they purely enforce secure transmission and limit exposure windows.
