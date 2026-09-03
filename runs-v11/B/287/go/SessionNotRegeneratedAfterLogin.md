## Verdict

Confirmed. The code fails to regenerate the session identifier after successful login, allowing an attacker to plant a session cookie before login and have it promoted to an authenticated session after login succeeds.

## Source

Line 48: `session, _ := store.Get(r, "session-name")` retrieves an existing session from the request cookie without validating ownership. If an attacker has set a session cookie on the victim's browser before login, this retrieves that attacker-planted session.

## Fix

Replace lines 48–52 with:

```go
// Invalidate the old session (if any) by setting MaxAge = -1
oldSession, _ := store.Get(r, "session-name")
oldSession.Options.MaxAge = -1
oldSession.Save(r, w)

// Create a fresh session with an empty ID, which causes Save() to mint a new random one
session, _ := store.New(r, "session-name")
session.Options.Secure = true
session.Options.HttpOnly = true
session.Options.SameSite = http.SameSiteLax

session.Values["userID"] = user.ID
session.Values["username"] = user.Username
```

## Explanation

The original code retrieves an existing session from the request cookie and adds authenticated user data to it without rotation. With `gorilla/sessions` CookieStore, the cookie itself is the session — there is no server-side identifier to rotate. An attacker can plant a session cookie on the victim's browser before login, and after the victim authenticates, that planted cookie becomes the authenticated session.

The fix invalidates the old session by setting `MaxAge = -1` and saving it (which erases any server-side record if using a server-side store), then creates a fresh session with `store.New()` whose empty ID triggers `Save()` to generate a new random one. The `Secure`, `HttpOnly`, and `SameSite` options harden the cookie against theft and CSRF. After the fresh session is created, authenticated user data is written to it, and the subsequent `Save()` at line 54 commits the fresh session with a new, unguessable identifier.

## Behaviour changes

- **Session lifecycle**: The old session (if present) is explicitly invalidated and a new one is created, breaking any pre-login session an attacker planted.
- **Cookie attributes**: The authenticated session now carries `Secure`, `HttpOnly`, and `SameSite=Lax`, which are recommended for session cookies to prevent theft and CSRF.
- **Timing**: An extra `Save()` call is added to erase the old session, so responses include two Set-Cookie headers (one for the invalidated old session, one for the new authenticated session) instead of one.
