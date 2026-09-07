## Verdict

exploitable

## Source

Attacker-controlled session cookie in the HTTP request, planted on the victim's browser before login (`r` parameter to `LoginHandler`).

## Fix

**Vulnerable code (lines 48–58):**

```go
session, _ := store.Get(r, "session-name")

// SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
session.Values["userID"] = user.ID
session.Values["username"] = user.Username

if err := session.Save(r, w); err != nil {
    log.Printf("failed to save session: %v", err)
    http.Error(w, "internal server error", http.StatusInternalServerError)
    return
}
```

**Fixed code:**

```go
// Obtain the existing session (whether attacker-planted or legitimate) and clear it completely.
// Replace session.Values wholesale to remove any attacker-controlled data before setting
// the authenticated user identity.
session, _ := store.Get(r, "session-name")
session.Values = make(map[interface{}]interface{})
session.Values["userID"] = user.ID
session.Values["username"] = user.Username

// Set security attributes on the session cookie.
session.Options.Secure = true
session.Options.HttpOnly = true
session.Options.SameSite = http.SameSiteLaxMode

if err := session.Save(r, w); err != nil {
    log.Printf("failed to save session: %v", err)
    http.Error(w, "internal server error", http.StatusInternalServerError)
    return
}
```

## Explanation

The vulnerability occurs because `gorilla/sessions` v1.4.0 (the latest release) does not support built-in session ID regeneration. When `store.Get(r, "session-name")` is called, it decodes any existing session cookie from the request—including one an attacker planted on the victim's browser before login. The code then adds the authenticated user ID to that same cookie, promoting the attacker-planted session to an authenticated one. An attacker can use this to bypass authentication: they plant a cookie on the victim's browser before login, and after the victim authenticates, the attacker uses their planted cookie with the authenticated user's ID.

The fix clears the session values completely by replacing `session.Values` with a fresh map before populating it with the authenticated user's data. This discards any attacker-planted data and ensures only the intended authenticated identity is written to the cookie. Additionally, security attributes (`Secure`, `HttpOnly`, `SameSite`) are set on the cookie to harden it against interception and cookie-theft attacks.

This approach matches the Go guidance for `CookieStore`: because the cookie IS the session (no server-side identifier exists), the only way to invalidate a planted session is to clear the values wholesale and emit a fresh cookie.

## Behaviour changes

- **session.Values is now explicitly cleared before use**: Replaces whatever data was in the decoded cookie with an empty map, then adds only the authenticated user's ID and username. This is a semantic change: old data in a planted cookie is discarded rather than carried forward.
- **Security attributes are now set on session.Options**: `Secure`, `HttpOnly`, and `SameSite=Lax` are new. This hardens the cookie against interception, client-side access, and CSRF-into-login. Reason: the CWE-287 guidance names these as standard hardening and they have no downside; the site must be served over HTTPS for `Secure=true` to have an effect, and doing so is already implied by the upstream comment mentioning "process-wide" initialization of the store.
- **The session cookie will now be unavailable to client-side JavaScript**: `HttpOnly=true` means JavaScript cannot read `document.cookie` or receive the session value; this is consistent with treating the cookie as a server-side authentication token rather than a JavaScript-visible state container.
- **The session cookie will not be sent on cross-origin requests**: `SameSite=Lax` restricts cookie transmission on same-site navigation and form submissions but not on cross-site requests initiated by the site's own code, preventing CSRF attacks where an attacker tricks the victim into submitting a request from a different site. The original code sent the cookie on all requests to the same host regardless of origin.

