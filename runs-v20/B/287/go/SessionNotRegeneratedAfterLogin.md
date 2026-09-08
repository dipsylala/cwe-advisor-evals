## Verdict

Exploitable. Confidence: high. CWE-287 (Improper Authentication) confirmed at `login_handler.go:51` in `LoginHandler`.

## Source

The session cookie on the incoming request (`r`'s `Cookie` header, read by `store.Get(r, "session-name")` at line 48). This value is attacker-influenceable: an attacker can plant a cookie on a victim's browser before the victim authenticates (via a subdomain, a response-splitting bug elsewhere, a shared device, or any mechanism that lets them set a cookie for the site). `store.Get` decodes whatever cookie is present and returns a `*sessions.Session` whose `Values` map carries anything that was already encoded into it.

Sink: line 51, `session.Values["userID"] = user.ID` (and the following `session.Values["username"] = ...`), which writes the newly authenticated identity into the `Values` map obtained from the pre-login cookie instead of starting a fresh session. `session.Save(r, w)` at line 54 then re-signs and re-issues that same map as the authenticated session cookie. Because the store is `sessions.NewCookieStore` (a `CookieStore`, not a server-side store), there is no separate session identifier to rotate - the encoded cookie itself is the session state - so the fix has to replace `Values` wholesale rather than layer the authenticated fields onto whatever decoded from the pre-existing cookie, per `cwe/287/go/INDEX.md`.

Sink contract (`store.Get` / `session.Save`, gorilla/sessions v1.4.0):
- **Returns**: `store.Get` returns `(*sessions.Session, error)`; the handler already discards the error (`session, _ := ...`), so a decode failure is silently treated as a fresh, empty session - unchanged by this fix.
- **Discards**: nothing new is surfaced by the fix; no additional output is produced.
- **Arguments left implicit**: `session.Options` was never set by the handler, so it fell through to the copy of `store.Options` that `store.Get` installs (`Path: "/"`, `MaxAge: 2592000`, with `Secure`/`HttpOnly`/`SameSite` left at their Go zero values - `false`/`false`/`SameSiteDefaultMode`). That means the pre-fix cookie was neither `Secure` nor `HttpOnly` and carried no `SameSite` attribute.
- **Failure behaviour**: `session.Save` returns an error the handler already logs and turns into a `500`; unchanged.

## Fix

### File: login_handler.go

```go
// Package auth implements the login endpoint for the accounts service.
//
// Session store: gorilla/sessions v1.4.0 (the latest release as of this
// writing; the project has no built-in session identifier rotation - see
// upstream issue #235, which remains open).
package auth

import (
	"log"
	"net/http"

	"github.com/gorilla/sessions"
)

// store is the process-wide gorilla/sessions cookie store, configured at
// startup with a secret loaded from the environment.
var store = sessions.NewCookieStore([]byte(sessionSecret()))

// User represents an authenticated account record loaded from the database.
type User struct {
	ID       int64
	Username string
	// PasswordHash is omitted from this sample; credential verification
	// happens in verifyCredentials before LoginHandler is reached.
}

// LoginHandler authenticates a submitted username/password pair and starts
// an authenticated session for the caller.
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user, err := verifyCredentials(username, password)
	if err != nil {
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}

	// Password check succeeded above. gorilla/sessions has no server-side
	// session identifier to rotate - with CookieStore the cookie itself is
	// the session - so the authenticated session is started by discarding
	// whatever values decoded from the request's existing cookie (including
	// one an attacker may have planted on the victim's browser before login)
	// instead of adding the authenticated user on top of them, and by
	// re-asserting the cookie's security attributes on the session that
	// carries the new authenticated identity.
	session, _ := store.Get(r, "session-name")
	session.Values = make(map[interface{}]interface{})
	session.Values["userID"] = user.ID
	session.Values["username"] = user.Username
	session.Options.Secure = true
	session.Options.HttpOnly = true
	session.Options.SameSite = http.SameSiteLaxMode

	if err := session.Save(r, w); err != nil {
		log.Printf("failed to save session: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("logged in"))
}

// verifyCredentials looks up the account by username and checks the
// submitted password against the stored hash. Implementation omitted -
// this sample is scoped to the session-handling gap in LoginHandler.
func verifyCredentials(username, password string) (*User, error) {
	panic("not implemented in this sample")
}

// sessionSecret loads the cookie-store signing key from the environment.
// Implementation omitted - not relevant to this sample.
func sessionSecret() string {
	panic("not implemented in this sample")
}
```

## Explanation

`store.Get` decodes whatever session cookie the request already carries and returns it with `IsNew = false`; the original code then wrote the newly authenticated `userID`/`username` fields directly into that decoded `Values` map, so a session an attacker had planted on the victim's browser before login was silently promoted to an authenticated session rather than discarded. Because the store is a `CookieStore` - all session state lives in the cookie itself, with no server-side identifier to rotate - the fix replaces `session.Values` with a fresh, empty map before populating it with the authenticated user's data, so nothing that decoded from the pre-login cookie survives into the authenticated one. The three added lines setting `session.Options.Secure`, `.HttpOnly`, and `.SameSite` close the companion gap the language guidance calls out at the same point: without them the authenticated cookie is neither `Secure` nor `HttpOnly` and carries no `SameSite` attribute, which would let it leak over plain HTTP, be read by injected script, or be replayed cross-site even after rotation. `library_recommendation`: none - `cwe/287/go/INDEX.md` records that gorilla/sessions v1.4.0 is the latest release and that its identifier-rotation request (upstream issue #235) remains open with no fixed release, so this is an application-level fix, not a dependency bump.

## Behaviour changes

- `session.Values` is now reset to an empty map before the authenticated fields are set, instead of being layered onto whatever the pre-login cookie decoded to. Reason: this is the fix itself - closing CWE-287 requires that no pre-authentication state (including anything an attacker planted) survive into the authenticated session. Any *legitimate* pre-login session data (e.g. a cart or CSRF token an unauthenticated visitor had accumulated) is intentionally discarded at login, per the loaded guidance's prescribed pattern for `CookieStore`; if this application relies on carrying such values forward, that would need to be re-added deliberately (e.g. re-derived, not carried over from the untrusted pre-login map).
- `session.Options.Secure`, `.HttpOnly`, and `.SameSite` are now explicitly set to `true`, `true`, and `http.SameSiteLaxMode`; previously they fell through to `store.Options`' zero values (`false`, `false`, `SameSiteDefaultMode`). Reason: the language guidance calls for setting these at the same point session rotation happens; without them the newly issued authenticated cookie would still be vulnerable to being sent over plain HTTP, read by injected script, or attached to a cross-site request. This does make the authenticated cookie non-functional over a plain-HTTP origin (`Secure` requires HTTPS) - if the service is not already served over HTTPS, that is a separate, pre-existing gap this fix surfaces rather than introduces.
- `session.Options.Path` and `.MaxAge` are left untouched (not reset), preserving the `Path: "/"` / 30-day `MaxAge` that `store.Get` copies from `store.Options`. Mutating the existing `*Options` struct's fields rather than replacing it with a new literal was a deliberate choice to avoid silently reverting these to their Go zero values.
- No other return value, argument, or discarded output changed; `store.Get`'s ignored error and `session.Save`'s error handling are unchanged from the original.

Verification: `go vet` and `gofmt -l` were run against the fixed file in an isolated scratch module (`module scratch`, `go 1.21`, requiring `github.com/gorilla/sessions v1.4.0` from the local module cache) - both completed with no output, i.e. no vet diagnostics and no formatting differences. Every name the fix introduces (`session.Options.Secure`, `.HttpOnly`, `.SameSite`, `http.SameSiteLaxMode`) is a documented field/constant of `gorilla/sessions.Options` and the standard-library `net/http` package, already imported in the original file; no new import was added.

Assumptions: the finding's SAST comment and the surrounding doc comment establish that the store is a `CookieStore` with no server-side identifier, matching the `cwe/287/go/INDEX.md` guidance branch for that case exactly, so no language- or store-type ambiguity had to be resolved. `verifyCredentials` and `sessionSecret` are out of scope (explicitly marked "implementation omitted" in the sample) and were left unmodified.
