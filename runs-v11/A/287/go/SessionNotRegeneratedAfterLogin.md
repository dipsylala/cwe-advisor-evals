## Verdict
Confirmed. The session is not regenerated after successful authentication, allowing session fixation attacks where an attacker plants a pre-login session cookie on the victim's browser, then upgrades it to an authenticated session by causing the victim to log in.

## Source
`evals/cases/287/go/SessionNotRegeneratedAfterLogin/login_handler.go`, lines 48-52.

The existing session cookie (possibly attacker-controlled) is retrieved at line 48 and promoted to an authenticated session at lines 51-52 without invalidating the pre-login session and issuing a fresh identifier.

## Fix
```go
// Invalidate the old (potentially attacker-planted) session.
oldSession, _ := store.Get(r, "session-name")
oldSession.Options.MaxAge = -1
oldSession.Save(r, w)

// Issue a fresh session with a new identifier.
session, _ := store.Get(r, "session-name")

session.Values["userID"] = user.ID
session.Values["username"] = user.Username

if err := session.Save(r, w); err != nil {
	log.Printf("failed to save session: %v", err)
	http.Error(w, "internal server error", http.StatusInternalServerError)
	return
}
```

## Explanation
Session fixation occurs when an attacker pre-sets a session cookie on a victim's browser before login, then waits for the victim to authenticate using that same session. Without regeneration, the attacker's known session ID becomes authenticated.

The fix invalidates any pre-existing session by setting `MaxAge = -1` before authentication is stored, then calls `store.Get()` again to obtain a fresh session. gorilla/sessions assigns a new random session identifier to each call to `Get()` on a fresh response (one without a valid existing session cookie), preventing the attacker from knowing the post-login session ID.

The two `Get()` calls are necessary because gorilla/sessions does not provide built-in session regeneration; calling `Get()` on the same request twice returns the same session object. Saving the invalidated session first clears the cookie from the client's perspective, so the second `Get()` issues a new one.
