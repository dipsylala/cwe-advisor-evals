## Verdict
exploitable

## Source
`sessionToken` returned from the `authenticate(username, password)` function at line 13

## Fix

**Vulnerable code (line 20-24):**
```go
http.SetCookie(w, &http.Cookie{
	Name:  "session_token",
	Value: sessionToken,
	Path:  "/",
})
```

**Fixed code:**
```go
http.SetCookie(w, &http.Cookie{
	Name:     "session_token",
	Value:    sessionToken,
	Path:     "/",
	Secure:   true,
	HttpOnly: true,
	SameSite: http.SameSiteStrictMode,
})
```

## Explanation
The session cookie containing a sensitive authentication token is transmitted without the `Secure` flag, allowing it to be sent over unencrypted HTTP connections where attackers can intercept it. The fix adds three security attributes: `Secure: true` restricts transmission to HTTPS only, `HttpOnly: true` prevents JavaScript from accessing the cookie via `document.cookie` (blocking XSS-based session theft), and `SameSite: http.SameSiteStrictMode` prevents cross-site request forgery attacks by withholding the cookie from requests originating from other sites. For a session cookie in an authentication flow, `SameSiteStrictMode` is appropriate; if this handler must support cross-site redirects (e.g., OAuth or federation), use `http.SameSiteLaxMode` instead.

## Behaviour changes
- `Secure: true` - The browser will refuse to send the cookie over HTTP connections; requires that the server enforces HTTPS deployment.
- `HttpOnly: true` - Client-side scripts can no longer read the cookie; legitimate client-side code that accesses `document.cookie` will not see this cookie.
- `SameSite: http.SameSiteStrictMode` - The cookie is withheld from all cross-site requests (including top-level navigations from other sites). If the application needs the cookie to be sent on inbound navigations from external sites (e.g., after OAuth or SAML redirect), downgrade to `http.SameSiteLaxMode`.
