## Verdict

exploitable

## Source

HTTP GET request to `/account/delete` endpoint, where the request originates from an attacker-controlled source (cross-origin) but is automatically sent with the victim's session cookie. The attacker can trigger this via an `<img>` tag or link embedded in an email, forum post, or attacker-controlled website.

## Fix

**Vulnerable code (line 31):**
```go
// Account deletion is convenience-linked from an email notification, so
// it is exposed as a plain GET so the link can be clicked directly.
// SAST FINDING: CWE-352 (Cross-Site Request Forgery) reported here. Sink is the next statement.
mux.HandleFunc("GET /account/delete", deleteAccountHandler(store))
```

**Fixed code:**
```go
// Account deletion GET renders a confirmation form (safe, no CSRF protection needed).
// The actual deletion POST is wrapped with CrossOriginProtection.
mux.HandleFunc("GET /account/delete", confirmDeleteAccountHandler())

// POST /account/delete performs the actual deletion with CSRF protection.
mux.Handle("POST /account/delete", protection.Handler(http.HandlerFunc(deleteAccountHandler(store))))

// confirmDeleteAccountHandler renders an HTML form for account deletion confirmation.
// This safe GET operation allows email links to work without triggering immediate deletion.
// The actual deletion requires a POST submission, which is protected by CrossOriginProtection.
func confirmDeleteAccountHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		html := `<!DOCTYPE html>
<html>
<head><title>Delete Account</title></head>
<body>
<h1>Delete Account</h1>
<p>Are you sure you want to delete your account? This action cannot be undone.</p>
<form method="POST" action="/account/delete">
    <button type="submit">Delete Account</button>
    <button type="button" onclick="window.history.back()">Cancel</button>
</form>
</body>
</html>`
		w.Write([]byte(html))
	}
}
```

## Explanation

The vulnerability exists because the handler performs a state-changing operation (account deletion) on a GET endpoint. Go's `http.CrossOriginProtection` middleware only validates non-safe HTTP methods (POST, PUT, DELETE, PATCH); it treats GET as safe by definition and never applies protection to it. This allows an attacker to trigger account deletion via a cross-origin request using an `<img>` tag or link, since the victim's browser automatically attaches the session cookie to any same-domain request.

The fix splits the operation into two endpoints: GET /account/delete now renders an HTML confirmation form (a safe operation requiring no CSRF protection), while POST /account/delete performs the actual deletion and is wrapped with `CrossOriginProtection`. This pattern preserves the convenience of email links (which must use GET) while preventing CSRF attacks on the state-changing operation. The CrossOriginProtection middleware validates the `Sec-Fetch-Site` header on the POST request and rejects cross-origin deletion attempts with a 403 Forbidden response.

## Behaviour changes

1. **GET /account/delete now returns an HTML confirmation page (200 OK) instead of deleting immediately (204 No Content).** Reason: GET is a safe operation and must not mutate state; email links now show a confirmation form rather than deleting on click. Users must submit the form to complete deletion.

2. **Actual deletion now requires POST instead of GET.** Reason: POST is a non-safe method that CrossOriginProtection validates; this brings account deletion into the CSRF-protected flow. The endpoint now rejects cross-origin POST requests via Fetch metadata header validation.

3. **Existing email links to GET /account/delete continue to work but now require explicit confirmation.** Reason: This prevents silent deletion from email link clicks while maintaining the convenience of the email workflow. Users must actively submit a form to delete their account.

4. **The confirmation handler must be added to the codebase as a new function.** Reason: Two distinct endpoints (confirmation form and deletion action) require two separate handlers.
