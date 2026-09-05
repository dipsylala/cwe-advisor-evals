## Verdict

Exploitable. The sensitive authentication token cookie is set without the `secure` flag on line 15, allowing it to be transmitted over unencrypted HTTP connections if the application or any network segment does not enforce HTTPS. This exposes the session token to man-in-the-middle interception and session hijacking.

## Source

`req.query.token` — the SSO provider's signed authentication token, passed as a query parameter after successful SSO authentication and extracted on line 8.

## Fix

### Vulnerable Code
```javascript
res.cookie('auth_token', authToken, {
  httpOnly: true,
  maxAge: 86400000,
});
```

### Fixed Code
```javascript
res.cookie('auth_token', authToken, {
  httpOnly: true,
  maxAge: 86400000,
  secure: true,
  sameSite: 'lax',
});
```

## Explanation

The fix adds the `secure: true` flag to enforce HTTPS-only transmission of the authentication cookie. This ensures the browser will only send the cookie on encrypted connections, preventing interception over unencrypted HTTP. The `sameSite: 'lax'` setting provides additional CSRF protection by allowing the cookie in same-site requests and top-level navigations (needed for SSO redirects) while blocking cross-site form submissions. Together, these attributes establish defense-in-depth: transport-layer protection via `secure` and request-context validation via `sameSite`.

## Behaviour changes

- **HTTPS enforcement required**: Cookies with `secure: true` will not be sent over HTTP connections. The application must enforce HTTPS in production; otherwise, the browser silently discards the cookie and the client remains unauthenticated. When deployed behind a reverse proxy, configure Express with `app.set('trust proxy', ...)` to ensure `secure` cookies are issued correctly.
- **CSRF attack mitigation**: `sameSite: 'lax'` blocks the cookie from cross-site POST requests and frame navigations, reducing CSRF exposure. The `lax` mode (rather than `strict`) preserves SSO/OAuth redirect flows by allowing the cookie on top-level navigations.
