## Verdict

CONFIRMED. The `http.SetCookie()` call at line 20 sets a sensitive session cookie (`session_token`) without the `Secure` flag, allowing it to be transmitted over unencrypted HTTP and intercepted. The cookie also lacks `HttpOnly` and `SameSite` attributes, leaving it vulnerable to XSS theft and CSRF.

## Source

Line 20 in `HttpCookieMissingSecure.go`:
```go
http.SetCookie(w, &http.Cookie{
	Name:  "session_token",
	Value: sessionToken,
	Path:  "/",
})
```

The `sessionToken` value is sensitive (returned from `authenticate()` and used for session identification) but the cookie struct omits all three security attributes: `Secure`, `HttpOnly`, and `SameSite`.

## Fix

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

Add three attributes to the cookie literal:
- `Secure: true` - restricts transmission to HTTPS only
- `HttpOnly: true` - blocks JavaScript access via `document.cookie`, mitigating XSS theft
- `SameSite: http.SameSiteStrictMode` - prevents cookie forwarding in cross-site requests, mitigating CSRF

## Explanation

The session token is sensitive authentication data that must never travel over plaintext HTTP. Setting `Secure: true` enforces HTTPS-only transmission at the browser level, ensuring the cookie is discarded if sent over HTTP. `HttpOnly: true` prevents client-side JavaScript from reading the token via `document.cookie`, eliminating a vector for XSS attackers to exfiltrate sessions. `SameSite: http.SameSiteStrictMode` restricts the cookie to same-origin requests only, preventing automatic forwarding in cross-site navigation and form submissions—the primary CSRF defence. Together, these attributes enforce the Go security model for sensitive cookies outlined in the language-specific guidance.

## Behaviour changes

- Cookies will be rejected by the browser if sent over HTTP, causing login to fail on non-HTTPS endpoints. This is the intended behaviour; ensure HTTPS is enforced site-wide.
- JavaScript on the page can no longer read `document.cookie`, reducing exposure to XSS-based session theft.
- Cookies will not be sent in cross-site navigation or form submissions, preventing CSRF attacks but potentially breaking intentional cross-site flows (e.g. OAuth redirects). Use `SameSiteLaxMode` if inbound links or SSO callbacks must carry the cookie.
