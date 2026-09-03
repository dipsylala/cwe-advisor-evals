## Verdict

Valid. The authentication token cookie is set without the `secure` flag, allowing transmission over unencrypted HTTP connections and exposing it to man-in-the-middle interception.

## Source

`req.query.token` (line 8) - authentication token provided by SSO provider in query parameter.

## Fix

Add `secure: true` to the cookie options object:

```javascript
res.cookie('auth_token', authToken, {
  httpOnly: true,
  secure: true,
  maxAge: 86400000,
});
```

## Explanation

The `secure` flag restricts cookie transmission to HTTPS connections only. Without it, the browser sends the authentication token over unencrypted HTTP, exposing it to network sniffing and man-in-the-middle attacks. The fix adds this flag to enforce transport-layer security for the sensitive session cookie. Combined with the existing `httpOnly` flag, this prevents both passive interception and XSS-based theft of the authentication token.

## Behaviour changes

- Cookies will only be transmitted over HTTPS connections; HTTP requests will not include the authentication cookie.
- This requires HTTPS to be enabled in production for the application to function correctly.
- Clients attempting to access the application over unencrypted HTTP will lose authentication state.
