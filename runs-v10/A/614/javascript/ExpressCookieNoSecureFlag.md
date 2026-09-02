## Verdict

The finding is confirmed. The authentication token cookie lacks the `secure` attribute, creating a risk that the session credential could be transmitted over unencrypted HTTP connections if the client makes a request to an HTTP endpoint, exposing it to network eavesdropping.

## Source

Line 15 in ExpressCookieNoSecureFlag.js calls `res.cookie()` to store an SSO authentication token in a session cookie. The cookie is configured with `httpOnly: true` and `maxAge: 86400000` but omits the `secure` attribute.

```javascript
res.cookie('auth_token', authToken, {
  httpOnly: true,
  maxAge: 86400000,
});
```

## Fix

Add `secure: true` to the cookie options object to restrict transmission to HTTPS only:

```javascript
res.cookie('auth_token', authToken, {
  httpOnly: true,
  secure: true,
  maxAge: 86400000,
});
```

## Explanation

The `secure` attribute directs the browser to send the cookie only over HTTPS connections. Without it, the browser will transmit the cookie over both HTTPS and HTTP, violating the confidentiality of the authentication token if the client ever makes an HTTP request. For an authentication credential exchanged in an HTTPS session, the `secure` flag is mandatory to prevent downgrade or accidental exposure on HTTP endpoints. The `httpOnly` flag already in place prevents JavaScript access (mitigating XSS-based theft), but `secure` adds the transport-layer protection needed for a sensitive token stored in a cookie.
