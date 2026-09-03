## Verdict

Confirmed: CWE-287 - Session Fixation via Missing Identifier Regeneration.

## Source

The vulnerability lies in line 48 of `login_handler.go`:

```go
session, _ := store.Get(r, "session-name")
```

This retrieves the session from the request cookie using `store.Get()`, which decodes any existing session cookie from the browser. If an attacker previously set a session cookie on the victim's browser before login, that attacker-controlled session cookie is promoted to an authenticated session without regeneration. The attacker retains access via the known session ID.

## Fix

Replace `store.Get()` with `store.New()` to discard the request cookie and create a fresh session:

```go
// Create a new session, discarding any pre-existing cookie from the request.
session, _ := store.New(r, "session-name")

// Set authenticated user data in the fresh session.
session.Values["userID"] = user.ID
session.Values["username"] = user.Username

if err := session.Save(r, w); err != nil {
	log.Printf("failed to save session: %v", err)
	http.Error(w, "internal server error", http.StatusInternalServerError)
	return
}
```

Additionally, harden the session cookie by setting `HttpOnly`, `Secure`, and `SameSite` flags in `sessions.Options` at initialization. For `CookieStore`, this replaces the cookie wholesale - there is no server-side session record to invalidate, so the new cookie becomes the authenticated session.

## Explanation

`gorilla/sessions` v1.4.0 has no built-in session ID regeneration (upstream issue #235 remains unfixed). The distinction between `store.Get()` and `store.New()` is that `Get` decodes and reuses the request cookie while `New` creates a fresh session with an empty ID, which `Save()` will populate with a random value.

Using `store.Get()` after login adopts any session cookie an attacker planted beforehand into the authenticated session. The attacker retains knowledge of the session ID and can hijack the user's authenticated session. Using `store.New()` instead discards the pre-login cookie and forces a fresh session ID to be issued on save, breaking the fixation chain.

This is a session fixation vulnerability because the attacker's control of the session ID persists through login - the remediation ensures only the application (via `Save()`) can determine the post-login session ID.

## Behaviour changes

- **Before**: A victim who visits an attacker-controlled page that sets a session cookie, then logs in on the legitimate site, ends up with a session whose ID the attacker knows and can reuse to hijack the authenticated session.
- **After**: Login always results in a new, randomly generated session ID. Any pre-login cookies are discarded. The attacker can no longer predict or reuse the authenticated session ID.
