## Verdict

Exploitable. The sensitive authentication token is set in a cookie without the `secure` flag, allowing it to be transmitted over unencrypted HTTP connections. This exposes the token to network sniffing and man-in-the-middle attacks.

## Source

Untrusted user input: `authToken = req.query.token` from the SSO callback's query parameter (line 8).

## Fix

**Vulnerable code** (line 15):
```javascript
res.cookie('auth_token', authToken, {
  httpOnly: true,
  maxAge: 86400000,
});
```

**Fixed code**:
```javascript
res.cookie('auth_token', authToken, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  maxAge: 86400000,
});
```

## Explanation

The fix adds two attributes to the cookie configuration: `secure: true` ensures the cookie is only transmitted over HTTPS connections, eliminating the risk of interception over unencrypted HTTP. The `sameSite: 'lax'` attribute mitigates CSRF attacks while preserving the cookie during top-level navigation from the external SSO provider (a cross-site redirect scenario where `strict` would prevent the cookie from being sent, breaking the authentication flow). Together, these attributes enforce the security properties required for handling sensitive authentication tokens.

## Behaviour changes

- `secure: true` ensures the browser will only send this cookie over HTTPS; if sent over HTTP, it will be silently dropped. This requires the application to enforce HTTPS in production. If Express is behind a proxy, ensure `app.set('trust proxy', ...)` is configured so Express correctly detects the encrypted connection.
- `sameSite: 'lax'` enforces that the cookie is sent on top-level navigations (including the SSO redirect from the external provider) and form submissions, but not in cross-site iframe contexts. This is appropriate for an SSO callback scenario where the cookie must be available after redirect from an external domain.
- These changes are additive to the existing behavior and do not alter the token's value, lifetime (`maxAge`), or JavaScript accessibility (`httpOnly`).
