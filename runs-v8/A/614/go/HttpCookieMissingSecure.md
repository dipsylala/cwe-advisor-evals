## Verdict

The `http.SetCookie` call on line 20 issues a session cookie containing sensitive authentication data without the `Secure` attribute, allowing the cookie to be transmitted over plaintext HTTP connections even when the initial authentication occurred via HTTPS.

## Source

```go
http.SetCookie(w, &http.Cookie{
	Name:  "session_token",
	Value: sessionToken,
	Path:  "/",
})
```

The `http.Cookie` struct is populated with only `Name`, `Value`, and `Path` fields. The missing `Secure` attribute defaults to `false`, which means the browser will send this cookie regardless of connection security.

## Fix

```go
http.SetCookie(w, &http.Cookie{
	Name:     "session_token",
	Value:    sessionToken,
	Path:     "/",
	Secure:   true,
	HttpOnly: true,
})
```

Add `Secure: true` to ensure the cookie is only transmitted over HTTPS. Additionally, set `HttpOnly: true` to prevent JavaScript from accessing the session token, closing a secondary attack vector.

## Explanation

CWE-614 occurs when a session cookie carrying sensitive data (here, an authentication token) lacks the `Secure` attribute in an HTTPS context. Without this flag, the browser will send the cookie over any HTTP connection to the same domain, including unencrypted connections to which an active network attacker has access. Setting `Secure: true` tells the browser to only transmit the cookie over HTTPS, binding its confidentiality to the encrypted channel.

The `HttpOnly: true` flag is a defense-in-depth measure that prevents document-level JavaScript (malicious or compromised via XSS) from reading the token, reducing the risk surface if the browser is compromised by client-side attacks.
