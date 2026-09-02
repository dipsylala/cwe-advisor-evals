## Verdict

exploitable

- cwe_id: CWE-614
- location: HttpCookieMissingSecure.go, line 20 (`http.SetCookie` sink; `http.Cookie{}` literal at lines 20-24)
- confidence: high

## Source

`sessionToken`, returned by `authenticate(username, password)` at line 13. It is a freshly issued session credential (`"tok-" + username` in this stub, standing in for a real session token) - a sensitive value that authorizes the session for its lifetime.

## Fix

Vulnerable code:

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

The `http.Cookie{}` literal carrying `sessionToken` set no security attributes, so Go's zero values applied: `Secure` false (cookie sent over plain HTTP as well as HTTPS, exposing it to interception on a downgraded or mixed-content connection) and `HttpOnly` false (readable via `document.cookie`, exposing it to any XSS on the page). The fix adds `Secure: true` so the browser only ever transmits this cookie over HTTPS, `HttpOnly: true` to close the related client-script-access gap on the same sensitive value, and `SameSite: http.SameSiteLaxMode` so the session cookie is withheld from cross-site subrequests while still being sent on ordinary top-level navigation (Lax, rather than Strict, was chosen because this handler is a plain login endpoint with no indication of an inbound-link or OAuth/SSO callback flow that Strict would break - see Behaviour changes). This app terminates its own connection (no reverse-proxy indication in this file), so `Secure: true` is set unconditionally rather than derived from `r.TLS`, matching the guidance's caution against trusting a proxy hop.

## Behaviour changes

- Added `Secure: true`: the cookie will no longer be sent by the browser over a plain-HTTP connection to this host. This is the intended remediation; it requires the site to actually serve this endpoint over HTTPS, which was not otherwise visible in this file and should be confirmed.
- Added `HttpOnly: true`: any client-side JavaScript on the page that currently reads `session_token` via `document.cookie` will stop being able to. No such access is present in this file; flagged in case the frontend relies on it.
- Added `SameSite: http.SameSiteLaxMode`: the cookie will no longer be attached to cross-site POST requests or non-navigational cross-site requests (previously sent under the browser's `SameSite=None`-like legacy default for unset cookies, since Go leaves `SameSite` unset unless the code sets it). Lax keeps it attached on top-level cross-site navigation (e.g. following a link into the app), so normal login-then-navigate flows are unaffected. This is a scope-tightening side effect of closing the CWE-614 finding via the language guidance's recommended pattern, not an independent change; assumption: no OAuth/SSO callback or cross-site form-post dependency on this specific cookie was evident in the provided file, so `Lax` was chosen over `Strict`.
- `Name`, `Value`, and `Path` are unchanged from the original.
