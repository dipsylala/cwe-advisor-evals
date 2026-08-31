## Verdict
**CWE-614 confirmed.** The session token cookie at line 20 is transmitted over HTTP and HTTPS without the `Secure` attribute, allowing interception over unencrypted connections.

## Source
```go
http.SetCookie(w, &http.Cookie{
	Name:  "session_token",
	Value: sessionToken,
	Path:  "/",
})
```

The `http.Cookie` struct is initialized without setting `Secure: true`.

## Fix
```go
http.SetCookie(w, &http.Cookie{
	Name:   "session_token",
	Value:  sessionToken,
	Path:   "/",
	Secure: true,
})
```

Add the `Secure: true` field to the cookie struct. This ensures the cookie is sent only over HTTPS connections and prevents transmission over unencrypted HTTP.

## Explanation
The `Secure` attribute on an HTTP cookie signals the browser to transmit the cookie only in HTTPS requests. Without it, the cookie will be sent over any HTTP connection, making it vulnerable to interception by a network attacker. Since the session token is sensitive authentication material, it must be marked `Secure` to enforce encrypted transport. Setting this flag is a mandatory defence when storing authentication credentials in cookies.
