## Verdict

Confirmed. The `http.Cookie` struct on line 20 lacks the `Secure`, `HttpOnly`, and `SameSite` attributes required to protect a session token over HTTPS.

## Source

The vulnerability occurs in the `loginHandler` function at line 20, where a session cookie carrying the authentication token is set without security attributes:

```go
http.SetCookie(w, &http.Cookie{
	Name:  "session_token",
	Value: sessionToken,
	Path:  "/",
})
```

The `sessionToken` is sensitive authentication data returned from `authenticate()` on line 13. Setting this cookie without the `Secure` flag allows it to be transmitted over unencrypted HTTP connections; without `HttpOnly`, client-side scripts can access it via `document.cookie`; and without `SameSite`, it is vulnerable to cross-site request forgery attacks.

## Fix

Add `Secure: true`, `HttpOnly: true`, and an explicit `SameSite` mode to the cookie struct:

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

The `Secure` flag ensures the cookie is only transmitted over HTTPS, preventing interception on unencrypted HTTP connections. The `HttpOnly` flag blocks access from JavaScript, mitigating XSS attacks that could steal the session token via `document.cookie`. The `SameSite: http.SameSiteLaxMode` setting protects against cross-site request forgery while allowing the cookie to be sent with same-site redirects and inbound navigation links, which is appropriate for a login flow.

## Behaviour changes

- Cookies will no longer be sent over plain HTTP connections.
- Client-side JavaScript cannot read the session cookie via `document.cookie`.
- The cookie will be sent with same-site redirects but withheld from cross-site requests (except inbound navigation), reducing CSRF exposure.
- Deployment must enforce HTTPS; the `Secure` flag requires TLS to function and will cause the browser to silently reject cookies if HTTPS is not available.
