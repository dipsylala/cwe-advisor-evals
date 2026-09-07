## Verdict

exploitable

## Source

Login endpoint receives username and password form values (lines 35-36), verified against stored credentials (line 38). Following successful password verification, the handler establishes an authenticated session.

## Sink

Line 48-51: `session, _ := store.Get(r, "session-name")` followed by assignment to `session.Values["userID"]` and `session.Values["username"]`.

## Fix

**Vulnerable code:**

```go
// Request's existing session cookie (if any - including one an attacker may have set)
// is promoted to authenticated session rather than replaced
session, _ := store.Get(r, "session-name")

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
// Create a fresh session instead of reusing any existing one
session, _ := store.New(r, "session-name")

// Set security flags to protect the new session cookie
session.Options.Secure = true
session.Options.HttpOnly = true
session.Options.SameSite = http.SameSiteLaxMode

session.Values["userID"] = user.ID
session.Values["username"] = user.Username

if err := session.Save(r, w); err != nil {
	log.Printf("failed to save session: %v", err)
	http.Error(w, "internal server error", http.StatusInternalServerError)
	return
}
```

## Explanation

The vulnerability is a session fixation attack enabled by `store.Get()`, which retrieves and reuses an existing session cookie if present in the request. An attacker can plant a cookie in a victim's browser before login, and if the application reuses that session ID for the authenticated session, the attacker retains access using the session ID they control. The fix replaces `store.Get()` with `store.New()` to create a fresh session object with a new random session ID that will be set in the response cookie. Since `gorilla/sessions` with `CookieStore` has no server-side session identifier, the session ID is entirely cookie-based, so creating a new session object forces the issuance of a new cookie to the client. The additional security flags (`Secure`, `HttpOnly`, `SameSite`) protect the cookie from theft via XSS and from being sent cross-site without the user's knowledge, hardening the session against related attacks.

## Behaviour changes

**New session options set:** `Secure`, `HttpOnly`, and `SameSite` are set on the session cookie. This changes the Set-Cookie response header to include these flags. The `Secure` flag instructs the browser to send the cookie only over HTTPS (safe in production environments). The `HttpOnly` flag prevents JavaScript from accessing the session cookie, mitigating XSS attacks. The `SameSite=Lax` flag restricts cross-site cookie transmission, mitigating CSRF attacks. These are hardening measures with no downside in standard deployments (HTTPS production, same-site frontend and backend). If the deployment mixes HTTP and HTTPS, `Secure=true` will cause cookies to be rejected on plain HTTP—this is correct behaviour and typically signals a configuration that should be fixed.

**Session identifier replaced:** `store.New()` instead of `store.Get()` causes a new random session ID to be generated and sent to the browser, invalidating any pre-existing session ID in the request. Any prior session data associated with the old ID is discarded. This is the intended behaviour: the authenticated session must not carry forward any state from a pre-login session.
