## Verdict

The code promotes an existing session (possibly planted by an attacker before login) to authenticated status without regenerating the session identifier, enabling session fixation attacks.

## Source

Line 48 retrieves the existing session with `store.Get(r, "session-name")` instead of creating a new one. The existing session ID is then elevated to authenticated status at lines 51-52 without invalidation. An attacker who plants a known session cookie on the victim's browser before login can hijack the authenticated session because the same ID persists after authentication.

## Fix

Replace `store.Get(r, "session-name")` with `store.New(r, "session-name")` to create a fresh session with a new identifier after successful credential verification:

```go
// Password check succeeded above. Create a new session with a fresh
// identifier to prevent session fixation attacks where a pre-planted
// session ID is reused after authentication.
session, _ := store.New(r, "session-name")

// Set authenticated user data in the new session.
session.Values["userID"] = user.ID
session.Values["username"] = user.Username

if err := session.Save(r, w); err != nil {
	log.Printf("failed to save session: %v", err)
	http.Error(w, "internal server error", http.StatusInternalServerError)
	return
}
```

## Explanation

Session fixation exploits occur when an application accepts a session identifier from an unauthenticated request and then elevates that identifier to authenticated status without regeneration. An attacker sets a known session ID on a victim's browser (via malicious link, CSP injection, or other means), waits for the victim to log in, then uses their known session ID to access the authenticated session.

The fix invalidates any pre-existing session and creates a new one after successful authentication. `store.New()` generates a fresh session with a new cryptographically random identifier, breaking the attacker's pre-planted session ID. This ensures that only sessions created after successful authentication are considered trusted, and any session ID an attacker planted beforehand becomes invalid.

Gorilla/sessions does not auto-rotate session IDs on a per-request basis (see upstream issue #235), so explicit regeneration at the authentication boundary is necessary. Creating a new session is the idiomatic way to handle this in gorilla/sessions and is the recommended practice for session fixation prevention.
