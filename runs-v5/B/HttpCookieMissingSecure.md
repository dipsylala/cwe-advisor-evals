## Verdict

exploitable (confidence: high)

## Source

`loginHandler` in `HttpCookieMissingSecure.go`, line 13: `sessionToken, ok := authenticate(username, password)` - a freshly issued session token, i.e. sensitive authentication state.

## Fix

Vulnerable code (lines 20-24):

```go
// SAST FINDING: CWE-614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute) reported here. Sink is the next statement.
http.SetCookie(w, &http.Cookie{
	Name:  "session_token",
	Value: sessionToken,
	Path:  "/",
})
```

Fixed code:

```go
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

The sink is the `http.Cookie{}` literal passed to `http.SetCookie()` at line 20. Go's `http.Cookie` sets no security attributes by default, so the literal as written omits `Secure`, meaning the browser will also transmit `session_token` over a plain HTTP connection to the same host, exposing it to network interception. The fix adds `Secure: true` so the cookie is sent only over HTTPS, closing the reported CWE-614 weakness. `HttpOnly: true` and an explicit `SameSite: http.SameSiteLaxMode` are added alongside it per the Go-specific guidance's Key Principles and Remediation Steps, which treat all three as required together for a sensitive cookie rather than `Secure` in isolation; `Lax` is used rather than `Strict` because this is a general session cookie and `Strict` would withhold it on inbound top-level navigation (e.g. an emailed link or SSO-style redirect back into the app), which the guidance flags as a behavioural risk of over-tightening `SameSite`. This handler has no reverse-proxy indirection in view, so `Secure: true` is set unconditionally rather than derived from request state, consistent with the guidance's warning against deriving it from `r.TLS` or forwarded headers.

## Behaviour changes

- Added `Secure: true` - the finding's required fix; cookie is no longer sent over plain HTTP.
- Added `HttpOnly: true` - not part of the CWE-614 finding itself, but the loaded Go guidance requires it alongside `Secure` for any sensitive cookie (blocks JavaScript/XSS access via `document.cookie`); previously any script on the page could read `session_token`.
- Added `SameSite: http.SameSiteLaxMode` - also required by the same guidance rather than leaving `SameSite` unset (which defaults to no restriction); `Lax` was chosen over `Strict` to avoid dropping the cookie on inbound top-level navigation into an authenticated page.
- `Name`, `Value`, `Path`, and the absence of `MaxAge`/`Expires`/`Domain` are unchanged - no session lifetime or scope change was made beyond the flags above.
