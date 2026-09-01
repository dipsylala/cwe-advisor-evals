## Verdict

The finding is **confirmed**. The cookie is set without the `secure` flag, allowing transmission over unencrypted HTTP connections.

## Source

Line 8: `const authToken = req.query.token;` - attacker-controlled input from SSO provider's query parameter.

## Fix

```javascript
res.cookie('auth_token', authToken, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  maxAge: 86400000,
});
```

Add `secure: true` to the options object to enforce HTTPS-only transmission. Add `sameSite: 'lax'` to protect against CSRF while permitting the SSO redirect to set the cookie on the callback response.

## Explanation

The original code sets an authentication token cookie without the `secure` flag. This allows the cookie to be transmitted over HTTP connections, exposing it to network sniffing, man-in-the-middle attacks, and session hijacking. Adding `secure: true` forces the browser to only transmit the cookie over HTTPS-encrypted connections. The `sameSite: 'lax'` value allows the cookie to be sent on cross-site top-level navigations (needed for the SSO callback redirect) while preventing transmission on subresource requests, defending against CSRF. The existing `httpOnly: true` prevents JavaScript access, mitigating XSS-based cookie theft.

## Behaviour changes

- Cookies set with `secure: true` will not be transmitted over HTTP connections.
- In development environments using HTTP (not HTTPS), the cookie will not be sent by the browser, which may break testing unless HTTPS is used.
- The application must be deployed over HTTPS for the `secure` flag to function; deployment over HTTP-only will fail to set the cookie entirely.
- If the application runs behind a reverse proxy, `app.set('trust proxy', ...)` must be configured for Express to recognize HTTPS connections and issue secure cookies correctly.
- `sameSite: 'lax'` permits the cookie to be sent on the SSO provider's cross-site redirect back to this endpoint (preserving SSO callback functionality) while restricting it on subresource requests.
